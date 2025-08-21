use reqwest;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct BlockchainClient {
    pub rpc_url: String,
    pub network_id: u64,
    client: reqwest::Client,
}

impl BlockchainClient {
    pub fn new(rpc_url: String, network_id: u64) -> Self {
        Self {
            rpc_url,
            network_id,
            client: reqwest::Client::new(),
        }
    }

    pub async fn get_block_number(&self) -> crate::Result<u64> {
        let response = self.make_rpc_call("eth_blockNumber", Vec::<String>::new()).await?;
        
        if let Some(result) = response.get("result") {
            let block_hex = result.as_str().ok_or("Invalid block number format")?;
            let block_number = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16)?;
            Ok(block_number)
        } else {
            Err("No result in response".into())
        }
    }

    pub async fn get_balance(&self, address: &str) -> crate::Result<u64> {
        let params = vec![address.to_string(), "latest".to_string()];
        let response = self.make_rpc_call("eth_getBalance", params).await?;
        
        if let Some(result) = response.get("result") {
            let balance_hex = result.as_str().ok_or("Invalid balance format")?;
            let balance = u64::from_str_radix(balance_hex.trim_start_matches("0x"), 16)?;
            Ok(balance)
        } else {
            Err("No result in response".into())
        }
    }

    pub async fn get_transaction_count(&self, address: &str) -> crate::Result<u64> {
        let params = vec![address.to_string(), "latest".to_string()];
        let response = self.make_rpc_call("eth_getTransactionCount", params).await?;
        
        if let Some(result) = response.get("result") {
            let nonce_hex = result.as_str().ok_or("Invalid nonce format")?;
            let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16)?;
            Ok(nonce)
        } else {
            Err("No result in response".into())
        }
    }

    pub async fn get_code(&self, address: &str) -> crate::Result<String> {
        let params = vec![address.to_string(), "latest".to_string()];
        let response = self.make_rpc_call("eth_getCode", params).await?;
        
        if let Some(result) = response.get("result") {
            Ok(result.as_str().unwrap_or("0x").to_string())
        } else {
            Err("No result in response".into())
        }
    }

    pub async fn call_contract(
        &self,
        to: &str,
        data: &str,
        from: Option<&str>,
    ) -> crate::Result<String> {
        let mut call_params = HashMap::new();
        call_params.insert("to", to);
        call_params.insert("data", data);
        
        if let Some(from_addr) = from {
            call_params.insert("from", from_addr);
        }

        let params = vec![serde_json::to_value(call_params)?, "latest".into()];
        let response = self.make_rpc_call("eth_call", params).await?;
        
        if let Some(result) = response.get("result") {
            Ok(result.as_str().unwrap_or("0x").to_string())
        } else {
            Err("No result in response".into())
        }
    }

    pub async fn estimate_gas(
        &self,
        to: &str,
        data: &str,
        from: Option<&str>,
        value: Option<&str>,
    ) -> crate::Result<u64> {
        let mut transaction = HashMap::new();
        transaction.insert("to", to);
        transaction.insert("data", data);
        
        if let Some(from_addr) = from {
            transaction.insert("from", from_addr);
        }
        
        if let Some(val) = value {
            transaction.insert("value", val);
        }

        let params = vec![serde_json::to_value(transaction)?];
        let response = self.make_rpc_call("eth_estimateGas", params).await?;
        
        if let Some(result) = response.get("result") {
            let gas_hex = result.as_str().ok_or("Invalid gas estimate format")?;
            let gas = u64::from_str_radix(gas_hex.trim_start_matches("0x"), 16)?;
            Ok(gas)
        } else {
            Err("No result in response".into())
        }
    }

    pub async fn get_gas_price(&self) -> crate::Result<u64> {
        let response = self.make_rpc_call("eth_gasPrice", Vec::<String>::new()).await?;
        
        if let Some(result) = response.get("result") {
            let price_hex = result.as_str().ok_or("Invalid gas price format")?;
            let price = u64::from_str_radix(price_hex.trim_start_matches("0x"), 16)?;
            Ok(price)
        } else {
            Err("No result in response".into())
        }
    }

    pub async fn get_transaction_receipt(&self, tx_hash: &str) -> crate::Result<TransactionReceipt> {
        let params = vec![tx_hash.to_string()];
        let response = self.make_rpc_call("eth_getTransactionReceipt", params).await?;
        
        if let Some(result) = response.get("result") {
            let receipt: TransactionReceipt = serde_json::from_value(result.clone())?;
            Ok(receipt)
        } else {
            Err("No result in response".into())
        }
    }

    pub async fn get_storage_at(&self, address: &str, position: &str) -> crate::Result<String> {
        let params = vec![address.to_string(), position.to_string(), "latest".to_string()];
        let response = self.make_rpc_call("eth_getStorageAt", params).await?;
        
        if let Some(result) = response.get("result") {
            Ok(result.as_str().unwrap_or("0x").to_string())
        } else {
            Err("No result in response".into())
        }
    }

    pub async fn trace_transaction(&self, tx_hash: &str) -> crate::Result<Vec<TraceEntry>> {
        let params = vec![tx_hash.to_string()];
        let response = self.make_rpc_call("debug_traceTransaction", params).await?;
        
        if let Some(result) = response.get("result") {
            let traces: Vec<TraceEntry> = serde_json::from_value(result.clone())?;
            Ok(traces)
        } else {
            Ok(Vec::new())
        }
    }

    async fn make_rpc_call<T: serde::Serialize>(
        &self,
        method: &str,
        params: T,
    ) -> crate::Result<Value> {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let response = self
            .client
            .post(&self.rpc_url)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let response_text = response.text().await?;
        let json_response: Value = serde_json::from_str(&response_text)?;

        if let Some(error) = json_response.get("error") {
            return Err(format!("RPC Error: {}", error).into());
        }

        Ok(json_response)
    }

    pub async fn get_network_id(&self) -> crate::Result<u64> {
        let response = self.make_rpc_call("net_version", Vec::<String>::new()).await?;
        
        if let Some(result) = response.get("result") {
            let network_id_str = result.as_str().ok_or("Invalid network ID format")?;
            Ok(network_id_str.parse()?)
        } else {
            Err("No result in response".into())
        }
    }

    pub fn is_connected(&self) -> bool {
        // This would typically involve making a test RPC call
        // For now, just return true if we have a valid URL
        !self.rpc_url.is_empty()
    }
}

impl Default for BlockchainClient {
    fn default() -> Self {
        Self::new("http://localhost:8545".to_string(), 1337)
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TransactionReceipt {
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "gasUsed")]
    pub gas_used: String,
    #[serde(rename = "cumulativeGasUsed")]
    pub cumulative_gas_used: String,
    pub status: String,
    pub logs: Vec<LogEntry>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct LogEntry {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TraceEntry {
    pub op: String,
    pub pc: u64,
    pub depth: u64,
    pub gas: u64,
    #[serde(rename = "gasCost")]
    pub gas_cost: u64,
    pub stack: Vec<String>,
    pub memory: Vec<String>,
    pub storage: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub struct BlockchainConfig {
    pub rpc_url: String,
    pub network_id: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub timeout_seconds: u64,
}

impl Default for BlockchainConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://localhost:8545".to_string(),
            network_id: 1337,
            gas_limit: 8_000_000,
            gas_price: 20_000_000_000, // 20 gwei
            timeout_seconds: 30,
        }
    }
}
