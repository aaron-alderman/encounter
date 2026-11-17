// Poll committed state and dispatch opt-in, bounded effects without blocking HTTP.
use crate::{Result, codex_stream::CodexStream, fail, ollama, process::{Meter, Programme}, websocket::Peer};
use serde_json::{Value, json};
use std::{sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc}, thread, time::{Duration, Instant}};

pub enum Model {
    Off,
    Ollama,
    Codex(CodexStream),
}

enum Delivery {
    Progress(Value),
    Finished(Value),
}

struct CodexWorker {
    job: Value,
    events: mpsc::Receiver<Delivery>,
    cancelled: Arc<AtomicBool>,
}

impl Drop for CodexWorker {
    fn drop(&mut self) { self.cancelled.store(true, Ordering::Release); }
}

pub struct Subscriber {
    pub operator: Value,
    pub fields: Value,
    pub after: u64,
    pub peer: Peer,
}

#[cfg(feature = "test-faults")]
struct OfflineRepair {
    prompt_sha256: String,
    response: Option<Value>,
}

pub struct Live {
    pub subscribers: Vec<Subscriber>,
    model: Model,
    cancel_codex: bool,
    codex_worker: Option<CodexWorker>,
    worker: Option<mpsc::Receiver<(Value, Value, Instant, Instant)>>,
    last: Instant,
    revision: Option<u64>,
    #[cfg(feature = "test-faults")]
    replay: Option<Value>,
    #[cfg(feature = "test-faults")]
    offline: Option<OfflineRepair>,
    #[cfg(feature = "test-faults")]
    experiment: Option<Value>,
    #[cfg(feature = "test-faults")]
    clock: Instant,
}

impl Live {
    pub fn new(model: Model, cancel_codex: bool) -> Result<Self> {
        #[cfg(feature = "test-faults")]
        let _enabled = matches!(model, Model::Ollama);
        #[cfg(feature = "test-faults")]
        let replay = if _enabled {
            std::env::var_os("ENCOUNTER_TEST_MODEL_REPLAY").map(|path| -> Result<Value> {
                if std::fs::metadata(&path)?.len() > 65_536 { return Err(fail("model replay fixture exceeds the bound")); }
                crate::rel::decode(&std::fs::read_to_string(path)?, "EncounterModelReplay")
            }).transpose()?
        } else { None };
        #[cfg(feature = "test-faults")]
        let experiment = if _enabled && replay.is_some() {
            std::env::var_os("ENCOUNTER_TEST_MODEL_CONTEXT").map(|path| -> Result<Value> {
                if std::fs::metadata(&path)?.len() > 8192 { return Err(fail("model context fixture exceeds the bound")); }
                crate::rel::decode(&std::fs::read_to_string(path)?, "EncounterModelContext")
            }).transpose()?
        } else { None };
        #[cfg(feature = "test-faults")]
        let offline = std::env::var_os("ENCOUNTER_TEST_OFFLINE_REPAIR").map(|path| -> Result<OfflineRepair> {
            if !_enabled || replay.is_none() || experiment.is_none() {
                return Err(fail("offline repair requires the rejected fixture and selector context"));
            }
            if std::fs::metadata(&path)?.len() > 65_536 { return Err(fail("offline repair fixture exceeds the bound")); }
            let fixture = crate::rel::decode(&std::fs::read_to_string(path)?, "EncounterOfflineRepair")?;
            let raw = fixture["reply"].as_str().ok_or_else(|| fail("offline repair requires a recorded reply"))?;
            let value = serde_json::from_str::<Value>(raw)?;
            let pin = fixture["promptSha256"].as_str().filter(|pin| pin.len() == 64 &&
                pin.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
                .ok_or_else(|| fail("offline repair requires a prompt pin"))?;
            Ok(OfflineRepair {
                prompt_sha256: pin.to_owned(),
                response: Some(json!({"error":"","raw":raw,"value":value})),
            })
        }).transpose()?;
        Ok(Self { subscribers: Vec::new(), model, cancel_codex, codex_worker: None, worker: None, last: Instant::now(), revision: None,
            #[cfg(feature = "test-faults")]
            replay,
            #[cfg(feature = "test-faults")]
            offline,
            #[cfg(feature = "test-faults")]
            experiment,
            #[cfg(feature = "test-faults")]
            clock: Instant::now(),
        })
    }

    pub fn events(programme: &Programme, meter: &Meter, snapshot: &Value,
        operator: &Value, fields: &Value, after: u64) -> Result<Value>
    {
        programme.run("app.events", json!({"snapshot":snapshot,"operator":operator,"fields":fields,"after":after}), &mut meter.clone())
    }

    pub fn publish(subscriber: &mut Subscriber, events: &Value) -> Result<()> {
        let rows = events.as_array().ok_or_else(|| fail("event subscription refused"))?;
        for event in rows {
            let sequence = event["sequence"].as_u64().filter(|value| *value > subscriber.after)
                .ok_or_else(|| fail("events must increase after the cursor"))?;
            let text = serde_json::to_string(event)?;
            let limit = if subscriber.peer.event_stream { 130_000 } else { 4096 };
            if text.len() > limit { return Err(fail("event exceeds the frame bound")); }
            if subscriber.peer.event_stream {
                let name = if event["name"] == "done" { "done" } else { "update" };
                subscriber.peer.publish(format!("event: {name}\ndata: {text}\n\n"))?;
            } else {
                subscriber.peer.publish(text)?;
            }
            subscriber.after = sequence;
        }
        Ok(())
    }

    fn deliver_codex(&mut self, programme: &Programme, meter: &Meter, basis: &str, profile: &str) -> Result<()> {
        for _ in 0..8 {
            let Some(worker) = &self.codex_worker else { return Ok(()) };
            let job = &worker.job;
            if self.cancel_codex
                && programme.run("app.agentCancel", json!({"snapshot":programme.snapshot()?,"job":job}), &mut meter.clone())? == true {
                worker.cancelled.store(true, Ordering::Release);
            }
            let (entry, field, event, terminal) = match worker.events.try_recv() {
                Ok(Delivery::Progress(event)) => ("app.agentProgress", "event", event, false),
                Ok(Delivery::Finished(event)) => ("app.agentResult", "response", event, true),
                Err(mpsc::TryRecvError::Empty) => return Ok(()),
                Err(mpsc::TryRecvError::Disconnected) =>
                    ("app.agentResult", "response", json!({"kind":"failed","message":"Codex worker stopped"}), true),
            };
            let mut input = json!({"snapshot":programme.snapshot()?,"basis":basis,"profile":profile,"job":job});
            input[field] = event;
            if terminal {
                self.codex_worker = None;
                self.revision = None;
            }
            programme.run(entry, input, &mut meter.clone())?;
        }
        Ok(())
    }

    pub fn tick(&mut self, programme: &Programme, meter: &Meter, basis: &str, profile: &str) -> Result<()> {
        if self.last.elapsed() < Duration::from_millis(100) { return Ok(()); }
        self.last = Instant::now();
        self.subscribers.retain(|subscriber| subscriber.peer.active());
        if let Some(worker) = &self.worker {
            match worker.try_recv() {
                Ok((job, response, _started, _available)) => {
                    self.worker = None;
                    self.revision = None;
                    let _validate = Instant::now();
                    let mut delivery = json!({
                        "snapshot":programme.snapshot()?,"basis":basis,"profile":profile,
                        "job":job,"response":response
                    });
                    #[cfg(feature = "test-faults")]
                    if let Some(context) = &self.experiment { delivery["context"] = context.clone(); }
                    let mut delivery_meter = meter.clone();
                    #[cfg(feature = "test-faults")]
                    let tracing = self.experiment.is_some() && std::env::var_os("ENCOUNTER_TEST_REPAIR_TRACE").is_some();
                    #[cfg(feature = "test-faults")]
                    if tracing { delivery_meter = meter.with_trace(); }
                    let result = programme.run("app.agentResult", std::mem::take(&mut delivery), &mut delivery_meter);
                    #[cfg(feature = "test-faults")]
                    if tracing {
                        eprintln!("repair-trace {}", json!({
                            "entry":"app.agentResult", "repair":job["repair"] == true, "basis":basis,
                            "replySha256":crate::rel::hash(response["raw"].as_str().unwrap_or("")),
                            "completed":result.is_ok(), "trace":delivery_meter.take_trace()
                        }));
                    }
                    result?;
                    #[cfg(feature = "test-faults")]
                    if self.experiment.is_some() {
                        eprintln!("replay-phase {}", json!({
                            "repair":job["repair"] == true,
                            "availableUs":_available.duration_since(self.clock).as_micros(),
                            "committedUs":self.clock.elapsed().as_micros(),
                            "modelUs":_available.duration_since(_started).as_micros(),
                            "validateCommitUs":_validate.elapsed().as_micros(),
                            "promptTokens":response["promptTokens"],"replyTokens":response["replyTokens"],
                            "generation":ollama::generation_options()?,
                        }));
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => { self.worker = None; self.revision = None; }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        self.deliver_codex(programme, meter, basis, profile)?;
        let snapshot = programme.snapshot()?;
        let revision = snapshot["revision"].as_u64();
        if self.revision == revision { return Ok(()); }
        self.revision = revision;
        self.subscribers.retain_mut(|subscriber| {
            Self::events(programme, meter, &snapshot, &subscriber.operator, &subscriber.fields, subscriber.after)
                .and_then(|events| Self::publish(subscriber, &events)).is_ok()
        });
        if self.worker.is_none() && self.codex_worker.is_none() {
            let mut input = json!({"snapshot":snapshot});
            if matches!(self.model, Model::Codex(_)) {
                input["basis"] = json!(basis);
                input["profile"] = json!(profile);
            }
            let job = programme.run("app.agentNext", input, &mut meter.clone())?;
            if !job.is_null() {
                if let Model::Codex(config) = &self.model {
                    let config = config.clone();
                    let (tx, rx) = mpsc::sync_channel(16);
                    let running = job.clone();
                    let cancelled = Arc::new(AtomicBool::new(false));
                    let signal = cancelled.clone();
                    thread::spawn(move || {
                        let response = config.turn(&running, &signal, |event| tx.send(Delivery::Progress(event))
                            .map_err(|_| fail("Codex consumer disconnected")))
                            .unwrap_or_else(|error| json!({"kind":"failed","message":error.to_string()}));
                        let _ = tx.send(Delivery::Finished(response));
                    });
                    self.codex_worker = Some(CodexWorker { job, events: rx, cancelled });
                    return Ok(());
                }
                let (tx, rx) = mpsc::sync_channel(1);
                #[cfg(feature = "test-faults")]
                let recorded = match (self.replay.take(), self.offline.as_mut()) {
                    (Some(value), offline) => {
                        if offline.is_some() && job["repair"] == true {
                            return Err(fail("offline rejected fixture received a repair job"));
                        }
                        Some(json!({"error":"","raw":value.to_string(),"value":value}))
                    }
                    (None, Some(offline)) => {
                        let prompt = job["prompt"].as_str().ok_or_else(|| fail("offline repair job has no prompt"))?;
                        if job["repair"] != true || crate::rel::hash(prompt) != offline.prompt_sha256 {
                            return Err(fail("offline repair job differs from the recorded prompt"));
                        }
                        Some(offline.response.take().ok_or_else(|| fail("offline repair fixture exhausted"))?)
                    }
                    (None, None) => None,
                };
                #[cfg(not(feature = "test-faults"))]
                let recorded: Option<Value> = None;
                thread::spawn(move || {
                    let started = Instant::now();
                    let response = recorded.unwrap_or_else(|| ollama::complete(&job)
                        .unwrap_or_else(|error| json!({"error":error.to_string(),"raw":"","value":null})));
                    let _ = tx.send((job, response, started, Instant::now()));
                });
                self.worker = Some(rx);
            }
        }
        Ok(())
    }
}
