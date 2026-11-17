// Transport only. Encounter supplies the bounded request and validates the reply.
use crate::{Result, fail, http_client};
use serde_json::{Value, json};
use std::time::Duration;

const ENDPOINT: &str = "http://127.0.0.1:11434";

fn request(path: &str, payload: Option<&Value>) -> Result<Value> {
    let bytes = payload.map(serde_json::to_vec).transpose()?;
    let response = http_client::send(http_client::Request {
        url: &format!("{ENDPOINT}{path}"), method: if payload.is_some() { "POST" } else { "GET" },
        headers: if payload.is_some() { &[("Content-Type", "application/json")] } else { &[] },
        body: bytes.as_deref(), timeout: Duration::from_secs(180), connect_timeout: Duration::from_secs(3),
        limit: 65_536, resolve: None, trust_anchor: None, restoring: false,
    }).map_err(|_| fail("Local Ollama request failed or timed out."))?;
    if response.status >= 400 { return Err(fail("Local Ollama request failed or timed out.")); }
    Ok(serde_json::from_slice(&response.body)?)
}

fn pinned(name: &str, digest: &str) -> Result<()> {
    let tags = request("/api/tags", None)?;
    let matched = tags["models"].as_array().is_some_and(|models|
        models.iter().any(|model| model["name"] == name && model["digest"] == digest));
    if !matched { return Err(fail("The installed Ollama model differs from the run pin.")); }
    Ok(())
}

pub(crate) fn generation_options() -> Result<Value> {
    let options = json!({"temperature":0.2,"num_predict":1100});
    #[cfg(feature = "test-faults")]
    let options = {
        let mut options = options;
        if let Some(seed) = std::env::var_os("ENCOUNTER_TEST_MODEL_SEED") {
            let seed = seed.to_str().and_then(|value| value.parse::<u32>().ok())
                .ok_or_else(|| fail("expected a benchmark model seed"))?;
            options["seed"] = json!(seed);
        }
        options
    };
    Ok(options)
}

pub fn complete(job: &Value) -> Result<Value> {
    let model = job["model"].as_str().ok_or_else(|| fail("expected model name"))?;
    let digest = job["digest"].as_str().ok_or_else(|| fail("expected model digest"))?;
    let prompt = job["prompt"].as_str().filter(|prompt| prompt.len() <= 32_768)
        .ok_or_else(|| fail("expected a bounded model prompt"))?;
    pinned(model, digest)?;
    let options = generation_options()?;
    let reply = request("/api/chat", Some(&json!({
        "model":model, "stream":false, "format":job["schema"],
        "messages":[{"role":"user","content":prompt}],
        "options":options
    })))?;
    pinned(model, digest)?;
    let raw = reply["message"]["content"].as_str().ok_or_else(|| fail("Ollama returned no text reply."))?;
    let decoded = serde_json::from_str::<Value>(raw).unwrap_or(Value::Null);
    Ok(json!({"raw":raw,"value":decoded,"error":"",
        "promptTokens":reply["prompt_eval_count"],"replyTokens":reply["eval_count"]}))
}
