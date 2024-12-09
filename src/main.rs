use ethabi::{Event, EventParam, ParamType};
use oasis_runtime_sdk::modules::rofl::app::prelude::*;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Application identifier for the ROFL system
const ROFL_APP_ID: &str = "rofl1qqn9xndja7e2pnxhttktmecvwzz0yqwxsquqyxdf";

/// Duration between consecutive blockchain event checks in seconds
const CHECK_INTERVAL_SECS: u64 = 15;

/// Number of blocks to keep in history per chain
const BLOCK_HISTORY_SIZE: usize = 10;

/// Configuration for supported blockchain networks
/// Each tuple contains:
/// - Network name
/// - RPC endpoint URL
/// - WETH contract address for that network
const SUPPORTED_CHAINS: &[(&str, &str, &str)] = &[
    (
        "Ethereum",
        "https://ethereum-rpc.publicnode.com",
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH CONTRACT ADDRESS
    ),
];

/// Creates an ERC20 Transfer event definition with the standard parameters:
/// - from (indexed): source address
/// - to (indexed): destination address
/// - value: amount transferred
fn create_transfer_event() -> Event {
    Event {
        name: "Transfer".to_string(),
        inputs: vec![
            EventParam {
                name: "from".to_string(),
                kind: ParamType::Address,
                indexed: true,
            },
            EventParam {
                name: "to".to_string(),
                kind: ParamType::Address,
                indexed: true,
            },
            EventParam {
                name: "value".to_string(),
                kind: ParamType::Uint(256),
                indexed: false,
            },
        ],
        anonymous: false,
    }
}

/// Application state for monitoring blockchain events
/// Maintains check intervals and tracking of processed blocks
struct EventCheckerApp {
    check_interval: Duration,
    processed_blocks: HashMap<String, u64>,
}

impl EventCheckerApp {
    /// Initializes a new EventCheckerApp instance with default configuration
    fn new() -> Self {
        Self {
            check_interval: Duration::from_secs(CHECK_INTERVAL_SECS),
            processed_blocks: HashMap::new(),
        }
    }

    /// Converts a byte array into its hexadecimal string representation
    fn encode_hex(bytes: &[u8]) -> String {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            hex.push_str(&format!("{:02x}", byte));
        }
        hex
    }

    /// Parses a hexadecimal string (with or without '0x' prefix) into a byte array
    /// Returns an error if the input string is malformed
    fn decode_hex(hex: &str) -> Result<Vec<u8>> {
        let hex = hex.trim_start_matches("0x");
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            if i + 2 > hex.len() {
                return Err(anyhow::anyhow!("Invalid hex string length"));
            }
            let byte = u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex string: {}", e))?;
            bytes.push(byte);
        }
        Ok(bytes)
    }

    /// Queries the blockchain for specific events within the specified block range
    /// 
    /// # Parameters
    /// * `rpc_url` - The blockchain node RPC endpoint
    /// * `contract_address` - The smart contract address to monitor
    /// * `event` - The event signature to filter for
    /// * `from_block` - Starting block number in hex
    /// * `to_block` - Ending block number in hex
    async fn check_event_on_chain(
        &self,
        rpc_url: &str,
        contract_address: &str,
        event: &Event,
        from_block: &str,
        to_block: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let sig_bytes: Vec<u8> = event.signature().as_bytes().to_vec();
        let event_signature = format!("0x{}", Self::encode_hex(&sig_bytes));

        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getLogs",
            "params": [{
                "fromBlock": from_block,
                "toBlock": to_block,
                "address": contract_address,
                "topics": [event_signature]
            }],
            "id": 1
        });

        let host = rpc_url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid RPC URL format"))?;

        let agent = rofl_utils::https::agent();
        let mut response = agent
            .post(rpc_url)
            .header("Content-Type", "application/json")
            .header("Host", host)
            .send_json(&payload)?;

        let body = response.body_mut().read_json::<serde_json::Value>()?;

        Ok(body["result"].as_array().unwrap_or(&Vec::new()).clone())
    }

    /// Retrieves the current block number from the specified blockchain
    /// Returns the block number in hexadecimal format
    async fn get_latest_block(&self, rpc_url: &str) -> Result<String> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        });

        let host = rpc_url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid RPC URL format"))?;

        let agent = rofl_utils::https::agent();
        let mut response = agent
            .post(rpc_url)
            .header("Content-Type", "application/json")
            .header("Host", host)
            .send_json(&payload)?;

        let body = response.body_mut().read_json::<serde_json::Value>()?;

        body["result"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("Invalid block number response"))
    }

    /// Main event monitoring loop
    /// 
    /// Continuously monitors all supported chains for Transfer events:
    /// 1. Fetches the latest block number
    /// 2. Processes any new blocks since last check
    /// 3. Decodes and logs any Transfer events found
    /// 4. Updates the last processed block number
    /// 5. Waits for the configured interval before next check
    async fn monitor_events(&self) -> Result<()> {
        let transfer_event = create_transfer_event();
        let mut processed_blocks = self.processed_blocks.clone();

        loop {
            for (chain_name, rpc_url, contract_address) in SUPPORTED_CHAINS {
                let latest_block = match self.get_latest_block(rpc_url).await {
                    Ok(block) => block,
                    Err(e) => {
                        println!("Error getting latest block for {}: {:?}", chain_name, e);
                        continue;
                    }
                };

                let latest_block_num = u64::from_str_radix(&latest_block[2..], 16)
                    .map_err(|e| anyhow::anyhow!("Failed to parse block number: {}", e))?;

                let highest_processed = processed_blocks
                    .entry(chain_name.to_string())
                    .or_insert(latest_block_num.saturating_sub(BLOCK_HISTORY_SIZE as u64));

                // Only process if we have new blocks
                if *highest_processed < latest_block_num {
                    let start_block = *highest_processed + 1;
                    
                    match self.check_event_on_chain(
                        rpc_url,
                        contract_address,
                        &transfer_event,
                        &format!("0x{:x}", start_block),
                        &format!("0x{:x}", start_block),
                    ).await {
                        Ok(logs) => {
                            for log in logs {
                                let mut decoded_log = serde_json::Map::new();

                                decoded_log.insert(
                                    "address".to_string(),
                                    json!(log["address"].as_str().unwrap_or("unknown")),
                                );
                                decoded_log.insert(
                                    "blockHash".to_string(),
                                    json!(log["blockHash"].as_str().unwrap_or("unknown")),
                                );
                                decoded_log.insert(
                                    "transactionHash".to_string(),
                                    json!(log["transactionHash"].as_str().unwrap_or("unknown")),
                                );
                                decoded_log.insert(
                                    "transactionIndex".to_string(),
                                    json!(log["transactionIndex"].as_str().unwrap_or("unknown")),
                                );
                                decoded_log.insert(
                                    "logIndex".to_string(),
                                    json!(log["logIndex"].as_str().unwrap_or("unknown")),
                                );
                                decoded_log.insert(
                                    "removed".to_string(),
                                    json!(log["removed"].as_bool().unwrap_or(false)),
                                );

                                if let Some(block_hex) = log["blockNumber"].as_str() {
                                    if let Ok(block_num) = u64::from_str_radix(&block_hex[2..], 16) {
                                        decoded_log.insert(
                                            "blockNumber".to_string(),
                                            json!({
                                                "hex": block_hex,
                                                "decimal": block_num
                                            }),
                                        );
                                    } else {
                                        decoded_log.insert("blockNumber".to_string(), json!(block_hex));
                                    }
                                }

                                if let Some(timestamp_hex) = log["blockTimestamp"].as_str() {
                                    if let Ok(timestamp) = u64::from_str_radix(&timestamp_hex[2..], 16)
                                    {
                                        decoded_log.insert(
                                            "blockTimestamp".to_string(),
                                            json!({
                                                "hex": timestamp_hex,
                                                "decimal": timestamp
                                            }),
                                        );
                                    } else {
                                        decoded_log
                                            .insert("blockTimestamp".to_string(), json!(timestamp_hex));
                                    }
                                }

                                if let Some(data) = log["data"].as_str() {
                                    if let Ok(data_bytes) = Self::decode_hex(data) {
                                        if let Ok(decoded) =
                                            ethabi::decode(&[ParamType::Uint(256)], &data_bytes)
                                        {
                                            decoded_log.insert(
                                                "data".to_string(),
                                                json!({
                                                    "hex": data,
                                                    "decoded": decoded[0].to_string()
                                                }),
                                            );
                                        } else {
                                            decoded_log.insert("data".to_string(), json!(data));
                                        }
                                    } else {
                                        decoded_log.insert("data".to_string(), json!(data));
                                    }
                                }

                                if let Some(topics) = log["topics"].as_array() {
                                    let mut decoded_topics = Vec::new();
                                    for (i, topic) in topics.iter().enumerate() {
                                        let topic_str = topic.as_str().unwrap_or("unknown");
                                        match i {
                                            1 | 2 => {
                                                let address = if topic_str.len() >= 26 {
                                                    format!("0x{}", &topic_str[26..])
                                                } else {
                                                    topic_str.to_string()
                                                };
                                                decoded_topics.push(json!({
                                                    "hex": topic_str,
                                                    "address": address
                                                }));
                                            }
                                            _ => decoded_topics.push(json!(topic_str)),
                                        }
                                    }
                                    decoded_log.insert("topics".to_string(), json!(decoded_topics));
                                }

                                println!("{}", serde_json::to_string(&decoded_log).unwrap());
                            }
                            
                            // Update the highest processed block by one
                            *highest_processed = start_block;
                        }
                        Err(e) => {
                            println!("Error checking {} chain at block {}: {:?}", chain_name, start_block, e);
                            // Don't update highest_processed on error, so we'll retry this block
                        }
                    }
                }
            }

            tokio::time::sleep(self.check_interval).await;
        }
    }
}

/// Implementation of the Oasis Runtime SDK App trait
#[async_trait]
impl App for EventCheckerApp {
    const VERSION: Version = sdk::version_from_cargo!();

    fn id() -> AppId {
        ROFL_APP_ID.into()
    }

    fn consensus_trust_root() -> Option<TrustRoot> {
        None
    }

    async fn run(self: Arc<Self>, _env: Environment<Self>) {
        println!("Event Checker App Running");

        if let Err(err) = self.monitor_events().await {
            println!("Error monitoring events: {:?}", err);
        }
    }
}

/// Application entry point
/// Initializes and starts the event monitoring system
fn main() {
    EventCheckerApp::new().start();
}
