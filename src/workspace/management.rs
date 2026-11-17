use super::{Fields, Request, Response, State, Workspace, equal, fail, header, invoke_text, response_status, string, timestamp};
use super::transport::{exchange, form, random, read_record, write_record};
use crate::Result;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs::{self, DirBuilder}, os::unix::fs::DirBuilderExt};

pub(super) struct OfficeOperation<'a>(&'a Workspace);
impl Drop for OfficeOperation<'_> {
    fn drop(&mut self) { self.0.state().active_office_operations -= 1; }
}

fn decision_history_update(history: &str, known: &str) -> Response {
    let mut order = Vec::new();
    let mut rows = serde_json::Map::new();
    let mut occurrences = std::collections::HashMap::new();
    let known_keys: Vec<&str> = if known.is_ascii() && known.len() <= 800 {
        (0..known.len() / 20).map(|i| &known[i * 20..(i + 1) * 20]).collect()
    } else { Vec::new() };
    if let Some((_, list)) = history.split_once("<ol class=\"identity-receipts\">")
        && let Some((list, _)) = list.split_once("</ol>") {
        for row in list.split("</li>").filter_map(|row| row.strip_prefix("<li>")) {
            let occurrence = occurrences.entry(row).or_insert(0_u32);
            let mut hash = Sha256::new();
            hash.update(occurrence.to_be_bytes());
            hash.update(row.as_bytes());
            *occurrence += 1;
            let key = hex::encode(&hash.finalize()[..10]);
            if !known_keys.contains(&key.as_str()) {
                rows.insert(key.clone(), json!(row));
            }
            order.push(key);
        }
    }
    if known_keys == order {
        return Response::empty(204);
    }
    Response::json(200, &json!({"order": order, "rows": rows}))
}

impl Workspace {
    pub(super) fn office_eval(&self, state: &State, operation: &str, person: &Value, details: Value) -> Result<Value> {
        let (now, timestamp) = timestamp();
        let selection = person["session"].as_str().and_then(|key| state.roles.get(key));
        let mut input = json!({"program":"office","operation":operation,"office":state.office,"person":person,
            "origin":self.runtime.origin,"now":now,"timestamp":timestamp,"selection":selection});
        input.as_object_mut().expect("office input").extend(details.as_object().expect("office details").clone());
        self.run(input)
    }

    fn office_write(&self, state: &mut State, record: &Value) -> Result<()> {
        write_record(&self.runtime.private.join("notes-office.json"), record, true)?;
        state.office = record.clone();
        Ok(())
    }

    pub(super) fn grant_active(&self, state: &State, grant: &Value) -> Result<bool> {
        if grant.is_null() { return Ok(false); }
        Ok(self.office_eval(state, "active-authority", &grant["person"], json!({"term":grant["term"]}))? == true)
    }

    pub(super) fn office_operation(&self, state: &mut State, grant: &Value) -> Result<Option<OfficeOperation<'_>>> {
        if !self.grant_active(state, grant)? { return Ok(None); }
        state.active_office_operations += 1;
        Ok(Some(OfficeOperation(self)))
    }

    pub(super) fn receipt(&self, state: &mut State, grant: &Value, decision: &str) -> Result<()> {
        let record = self.office_eval(state, "record", &grant["person"], json!({"term":grant["term"],"decision":decision}))?;
        self.office_write(state, &record)
    }

    pub(super) fn management(&self, request: &Request, query: &Fields, route: &Value) -> Result<Response> {
        let gateway_authenticated = equal(header(request, "authorization"), &self.runtime.authorization);
        let observe_claimipedia = |decision| {
            if route["program"] == "claimipedia" {
                let _ = self.claimipedia_admission(request, gateway_authenticated, false, decision);
            }
        };
        if !gateway_authenticated {
            observe_claimipedia("gateway-refused");
            return Ok(Response::text(403, "Access refused."));
        }
        if !matches!(request.method.as_str(), "GET" | "POST") {
            observe_claimipedia("method-refused");
            return Ok(Response::text(405, "Method refused."));
        }
        if request.method == "POST" && header(request, "origin") != self.runtime.local_origin {
            observe_claimipedia("origin-refused");
            return Ok(Response::text(403, "Origin refused."));
        }
        let program = string(&route["program"])?;
        let fragment = route["fragment"] == true;
        let mut state = self.state();
        if self.runtime.steward.is_empty() && program != "identity-overview" {
            observe_claimipedia("office-unconfigured");
            return Ok(Response::empty(403));
        }
        let identity = json!({"id":request.headers.get("x-temple-principal"),
            "email":request.headers.get("x-temple-email"),"session":request.headers.get("x-temple-actor-session")});
        let actor = self.office_eval(&state, "actor", &identity, json!({"bootstrapEmail":self.runtime.steward}))?;
        let person = &actor["person"];
        if person.is_null() {
            observe_claimipedia("identity-refused");
            return Ok(Response::empty(403));
        }
        if !actor["write"].is_null() { self.office_write(&mut state, &actor["write"])?; }
        if program == "identity-overview" {
            self.expire_mentions_grant(&mut state, person)?;
            let profile = self.office_eval(&state, "identity-overview", person, json!({}))?;
            let configured = !state.credentials.is_null();
            drop(state);
            let document = self.run(json!({"program":"identity","operation":"overview","profile":profile,
                "configured":configured,"origin":self.runtime.origin,"style":self.release.style}))?;
            return Ok(self.page(200, string(&document)?));
        }
        if program == "claimipedia" {
            drop(state);
            let native = if request.method == "POST" { "method-refused" } else { "admit" };
            let decision = self.claimipedia_admission(request, true, true, native)?;
            return match decision.as_str() {
                Some("admit") => self.corpus(request, query, program, fragment, false),
                Some("method-refused") => Ok(Response::text(405, "Method refused.")),
                Some("gateway-refused" | "origin-refused" | "office-unconfigured" | "identity-refused") =>
                    Ok(Response::empty(403)),
                _ => Err(fail("invalid Encounter Claimipedia admission decision")),
            };
        }
        if program == "aster" {
            drop(state);
            return self.corpus(request, query, program, fragment, request.method == "POST");
        }
        if program == "keys" && request.method != "GET" {
            return Ok(Response::text(405, "Method refused."));
        }
        if program == "notes-assurance" {
            if request.method != "GET" {
                return Ok(Response::text(405, "Method refused."));
            }
            let history = self.office_eval(&state, "decision-history", person, json!({}))?;
            drop(state);
            let history = string(&history)?;
            if fragment && query.get("updates") == Some("1") {
                return Ok(decision_history_update(history, query.get("known").unwrap_or("")));
            }
            return self.render(200, program, history, fragment);
        }
        if program == "acting-as" {
            let (status, content) = self.office_view(&mut state, person, Some(request))?;
            drop(state);
            return self.render(status, program, &content, fragment);
        }
        let read_mentions = if program == "x-mentions" {
            let access = self.office_eval(&state, "mentions-access", person, json!({"method":request.method}))?;
            if !access["write"].is_null() { self.office_write(&mut state, &access["write"])?; }
            access["readOnly"] == true
        } else { false };
        let grant = self.office_eval(&state, "authority", person, json!({}))?;
        let Some(operation) = self.office_operation(&mut state, &grant)? else {
            if read_mentions {
                let content = self.mentions_content(&state, "", "", true)?;
                drop(state);
                return self.render(200, program, &content, fragment);
            }
            if program == "network" {
                let (_, content) = self.office_view(&mut state, person, None)?;
                drop(state);
                return self.render(403, "acting-as", &content, false);
            }
            drop(state);
            if matches!(program, "certificates" | "keys") {
                let content = self.run(json!({"program":"identity","operation":"inventory","view":program,"notice":"steward"}))?;
                return self.render(403, program, string(&content)?, fragment);
            }
            let content = self.run(json!({"program":"workspace","operation":"refused","programName":program,"origin":self.runtime.origin}))?;
            if program == "identity-management" {
                return self.identity_provider_page(403, string(&content)?, fragment);
            }
            return self.render(403, program, string(&content)?, fragment);
        };
        drop(state);
        let result = match program {
            "versions" => {
                if request.method == "POST" {
                    self.receipt(&mut self.state(), &grant, "Authorized a version management submission")?;
                }
                self.versions(request, fragment)
            }
            "network" => self.network(request),
            "certificates" if request.method == "POST" => self.certificate_renewal(request, &grant, fragment),
            "certificates" | "keys" => self.certificate_inventory(program, fragment, 200, Value::Null, ""),
            "x-mentions" => self.mentions_setup(request, query, &grant, fragment),
            "identity-management" => self.identity_settings(request, &grant, fragment),
            _ => Err(fail("invalid workspace management programme")),
        };
        drop(operation);
        result
    }

    fn expire_mentions_grant(&self, state: &mut State, person: &Value) -> Result<()> {
        if !state.office["delegation"].is_null() {
            let record = self.office_eval(state, "expire", person, json!({}))?;
            if !record.is_null() { self.office_write(state, &record)?; }
        }
        Ok(())
    }

    fn office_view(&self, state: &mut State, person: &Value, request: Option<&Request>) -> Result<(u16, String)> {
        let valid = request.is_some_and(|request| request.method == "POST" && form(request, 1024, false));
        let fields = Fields::parse(request.filter(|_| valid).map(|r| r.body.as_slice()).unwrap_or_default());
        let mut id = random::<16>()?;
        id[6] = (id[6] & 0x0f) | 0x40;
        id[8] = (id[8] & 0x3f) | 0x80;
        let id = hex::encode(id);
        let id = format!("{}-{}-{}-{}-{}", &id[..8], &id[8..12], &id[12..16], &id[16..20], &id[20..]);
        let response = self.office_eval(state, "view", person, json!({"method":request.map(|r|r.method.as_str()).unwrap_or("GET"),
            "inUse":state.active_office_operations,"form":valid,"fieldCount":fields.len(),"id":id,
            "fields":{"action":fields.get("action"),"email":fields.get("email"),"offerId":fields.get("offerId"),
                "grantId":fields.get("grantId"),"duration":fields.get("duration")}}))?;
        if !response["write"].is_null() { self.office_write(state, &response["write"])?; }
        if !response["selection"].is_null() {
            let (now, _) = timestamp();
            state.roles.retain(|_, role| role["term"] == state.office["term"] &&
                role["expires"].as_i64().is_some_and(|time| time > now));
            state.roles.insert(string(&person["session"])?.to_owned(), response["selection"].clone());
        }
        Ok((response_status(&response)?, string(&response["content"])?.to_owned()))
    }

    fn certificate_inventory(&self, program: &str, fragment: bool, status: u16, review: Value, message: &str) -> Result<Response> {
        let inventory = self.runtime.certificate_inventory.as_deref()
            .and_then(|origin| exchange(origin, "/inventory", "GET", &[], None, "3").ok())
            .filter(|result| result.status == 200 && result.body.len() <= 16_384
                && result.content_type.starts_with("application/json"))
            .and_then(|result| serde_json::from_slice::<Value>(&result.body).ok())
            .filter(|value| value["certificates"].as_array().is_some_and(|rows| rows.len() == 2)
                && value["keys"].as_array().is_some_and(|rows| rows.len() == 4));
        let status = if inventory.is_some() { status } else { 503 };
        let rollover = self.runtime.certificate_rollover.clone().filter(|_| program == "certificates").map(|mut plan| {
            let state = self.state();
            let digest = plan["digest"].as_str().expect("validated rollover digest");
            plan["approved"] = json!(Self::rollover_approved(&state, digest));
            plan["available"] = json!(plan["deadline"].as_i64().is_some_and(|deadline| timestamp().0 < deadline));
            plan
        });
        let content = self.run(json!({"program":"identity","operation":"inventory","view":program,"inventory":inventory,
            "renewalAvailable":self.runtime.certificate_renewal.is_some(),"review":review,"message":message,"rollover":rollover}))?;
        self.render(status, program, string(&content)?, fragment)
    }

    fn certificate_renewal(&self, request: &Request, grant: &Value, fragment: bool) -> Result<Response> {
        let render = |status, review, message| self.certificate_inventory("certificates", fragment, status, review, message);
        if !form(request, 1024, true) {
            return render(400, Value::Null, "Use the certificate renewal form.");
        }
        let fields = Fields::parse(&request.body);
        if fields.get("action") == Some("approve-rollover") {
            let Some(plan) = self.runtime.certificate_rollover.as_ref().filter(|plan|
                fields.len() == 2 && plan["digest"].as_str() == fields.get("digest") &&
                plan["deadline"].as_i64().is_some_and(|deadline| timestamp().0 < deadline)) else {
                return render(409, Value::Null, "The staged issuer rollover plan changed or expired.");
            };
            let digest = string(&plan["digest"])?;
            let mut state = self.state();
            if Self::rollover_approved(&state, digest) {
                drop(state);
                return render(409, Value::Null, "This issuer rollover plan already has steward approval.");
            }
            self.receipt(&mut state, grant, &Self::rollover_decision(digest))?;
            drop(state);
            return render(200, Value::Null, "Steward approval recorded for the staged issuer rollover.");
        }
        let Some((origin, authorization)) = &self.runtime.certificate_renewal else {
            return render(503, Value::Null, "The managed certificate renewal service is unavailable.");
        };
        let session = string(&grant["person"]["session"])?;
        let (now, _) = timestamp();
        let submit = |path, body: Value, seconds| -> Result<Value> {
            let wire = body.to_string();
            let result = exchange(origin, path, "POST", &[("Authorization", authorization.as_str()),
                ("Content-Type", "application/json")], Some(&wire), seconds)?;
            if result.status != 200 || result.body.len() > 16_384 ||
                !result.content_type.starts_with("application/json") {
                return Err(fail("managed certificate operation refused"));
            }
            Ok(serde_json::from_slice(&result.body)?)
        };
        if fields.get("action") == Some("review") && fields.len() == 2 {
            let Some(target @ ("server" | "desktop")) = fields.get("target") else {
                return render(400, Value::Null, "Choose a managed certificate.");
            };
            let Ok(mut review) = submit("/review", json!({"target":target}), "5") else {
                return render(503, Value::Null, "The managed certificate could not be reviewed.");
            };
            let Some(digest) = review["digest"].as_str() else {
                return render(503, Value::Null, "The managed certificate could not be reviewed.");
            };
            if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                || review["plan"]["target"] != target {
                return render(503, Value::Null, "The managed certificate could not be reviewed.");
            }
            let mut pending = self.runtime.certificate_reviews.lock().expect("certificate reviews");
            pending.retain(|_, review| review["deadline"].as_i64().is_some_and(|deadline| deadline > now));
            pending.remove(session);
            if review["plan"]["eligible"] == true {
                if pending.len() >= 64 { return render(503, Value::Null, "Try again after outstanding reviews expire."); }
                review["id"] = json!(super::token::<18>()?);
                pending.insert(session.to_owned(), json!({"review":review,"grant":grant,"deadline":now+300_000}));
            }
            drop(pending);
            return render(200, review, "");
        }
        if fields.get("action") != Some("approve") || fields.len() != 3 {
            return render(400, Value::Null, "Review the managed certificate before approving.");
        }
        let mut pending = self.runtime.certificate_reviews.lock().expect("certificate reviews");
        let Some(entry) = pending.get(session).filter(|entry| {
            entry["grant"] == *grant && entry["deadline"].as_i64().is_some_and(|deadline| deadline > now)
                && entry["review"]["id"].as_str().is_some_and(|id| Some(id) == fields.get("reviewId"))
                && entry["review"]["digest"].as_str().is_some_and(|digest| Some(digest) == fields.get("digest"))
        }) else {
            return render(409, Value::Null, "The renewal review changed or expired. Review again.");
        };
        let review = entry["review"].clone();
        pending.remove(session);
        drop(pending);
        let Ok(result) = submit("/renew", json!({"target":review["plan"]["target"],
            "requestedAt":review["plan"]["requestedAt"],"digest":review["digest"]}), "22") else {
            return render(409, Value::Null, "The renewal could not complete. Check the installed certificate and review again.");
        };
        if result["renewed"]["target"] != review["plan"]["target"] || result["renewed"]["expires"] != review["plan"]["proposedExpiry"] {
            return render(503, Value::Null, "The renewal result could not be confirmed.");
        }
        let serial = string(&result["renewed"]["serial"])?;
        let expires = string(&result["renewed"]["expires"])?;
        let target = string(&result["renewed"]["target"])?;
        self.receipt(&mut self.state(), grant, &format!("Renewed managed Super CRM {target} certificate {serial} through {expires}"))?;
        render(200, Value::Null, &format!("Renewed the {target} certificate. New expiry: {expires}"))
    }

    fn rollover_decision(digest: &str) -> String {
        format!("Approved managed Super CRM issuer rollover {digest}")
    }

    fn rollover_approved(state: &State, digest: &str) -> bool {
        let decision = Self::rollover_decision(digest);
        state.office["receipts"].as_array().is_some_and(|receipts| receipts.iter().any(|receipt|
            receipt["term"] == state.office["term"] && receipt["decision"].as_str() == Some(&decision)))
    }

    fn identity_settings(&self, request: &Request, grant: &Value, fragment: bool) -> Result<Response> {
        let valid = request.method == "POST" && form(request, 4096, false);
        let fields = Fields::parse(if valid { &request.body } else { &[] });
        let credentials = if valid {
            json!({"clientId":fields.get("clientId"),"clientSecret":fields.get("clientSecret")})
        } else { Value::Null };
        let mut state = self.state();
        let response = self.run(json!({"program":"identity","origin":self.runtime.origin,"method":request.method,
            "configured":!state.credentials.is_null(),"form":valid,"fieldCount":fields.len(),"credentials":credentials}))?;
        if response["save"] == true {
            self.receipt(&mut state, grant, "Authorized replacing X provider credentials")?;
            write_record(&self.runtime.private.join("x-credentials.json"), &credentials, true)?;
            state.credentials = credentials;
            state.credential_revision += 1;
        }
        drop(state);
        self.identity_provider_page(response_status(&response)?, string(&response["content"])?, fragment)
    }

    fn identity_provider_page(&self, status: u16, content: &str, fragment: bool) -> Result<Response> {
        if fragment { return Ok(self.page(status, content)); }
        let document = self.run(json!({"program":"identity","operation":"document","title":"X sign-in settings",
            "origin":self.runtime.origin,"style":self.release.style,"content":content}))?;
        Ok(self.page(status, string(&document)?))
    }

    fn claimipedia_admission(&self, request: &Request, gateway_authenticated: bool, actor_verified: bool, native: &str) -> Result<Value> {
        let input = json!({"program":"workspace","operation":"claimipedia-admission",
            "gatewayAuthenticated":gateway_authenticated,"actorVerified":actor_verified,
            "officeConfigured":!self.runtime.steward.is_empty(),"method":request.method,
            "originTrusted":header(request, "origin")==self.runtime.local_origin});
        let evaluated = self.run(input);
        let encounter = evaluated.as_ref().ok().and_then(Value::as_str).filter(|decision|
            matches!(*decision, "gateway-refused" | "method-refused" | "origin-refused" | "office-unconfigured" | "identity-refused" | "admit"))
            .unwrap_or("error");
        let authority = if actor_verified { "encounter" } else { "native" };
        eprintln!("Notes admission comparison program=claimipedia native={native} encounter={encounter} agree={} authority={authority}", native == encounter);
        evaluated
    }

    fn corpus(&self, request: &Request, query: &Fields, view: &str, fragment: bool, submitted: bool) -> Result<Response> {
        let form_fields;
        let fields = if submitted {
            if !form(request, 4096, true) { return Ok(Response::text(400, "Submit the Ask Aster form.")); }
            form_fields = Fields::parse(&request.body);
            if form_fields.len() != 1 || form_fields.get("q").is_none() {
                return Ok(Response::text(400, "Submit one question."));
            }
            &form_fields
        } else { query };
        let q = fields.get("q").unwrap_or_default();
        let claim = fields.get("claim").unwrap_or_default();
        let evidence = fields.get("evidence").unwrap_or_default();
        if q.encode_utf16().count() > 240 || claim.encode_utf16().count() > 160 || evidence.encode_utf16().count() > 160 {
            return Ok(Response::text(400, "The search is too long."));
        }
        let map = fields.get("map").filter(|map| matches!(*map, "ecology" | "index")).unwrap_or_default();
        let topic = fields.get("topic").filter(|topic| matches!(*topic,
            "Descriptive" | "Causal" | "Predictive" | "Definitional" | "Procedural" | "Normative")).unwrap_or_default();
        let html = invoke_text(&self.release.corpus, &json!({"view":view,"submitted":submitted,"q":q,"claim":claim,
            "evidence":evidence,"map":map,"topic":topic}))?;
        let mut mounted = html;
        for attr in ["href", "action"] {
            for prefix in ["identity-management", "game"] {
                mounted = mounted.replace(&format!(" {attr}=\"/{prefix}/"), &format!(" {attr}=\"{}/{prefix}/", self.runtime.origin));
            }
        }
        self.render(200, view, &mounted, fragment)
    }

    fn network(&self, request: &Request) -> Result<Response> {
        let mut headers = vec![("Authorization", self.runtime.authorization.as_str())];
        let body = if request.method == "POST" {
            if !form(request, 4096, true) { return Ok(Response::text(400, "Submit the Network settings form.")); }
            headers.push(("Content-Type", "application/x-www-form-urlencoded"));
            headers.push(("Origin", &self.runtime.network));
            Some(std::str::from_utf8(&request.body)?)
        } else { None };
        match exchange(&self.runtime.network, "/network/notes", &request.method, &headers, body, "22") {
            Ok(result) if result.content_type.starts_with("text/html") && (200..600).contains(&result.status) =>
                self.render(result.status, "network", std::str::from_utf8(&result.body)?, false),
            _ => Ok(Response::text(503, "Network settings are unavailable.")),
        }
    }

    fn versions(&self, request: &Request, fragment: bool) -> Result<Response> {
        let valid = request.method == "POST" && form(request, 1024, false);
        let fields = Fields::parse(if valid { &request.body } else { &[] });
        let _serial = self.runtime.versions.lock().expect("workspace version submissions");
        let local_path = self.runtime.private.join("life-board-local.json");
        let proposals_path = self.runtime.private.join("life-board-move-proposals");
        let local = read_record(&local_path)?;
        let mut proposals = Vec::new();
        match fs::read_dir(&proposals_path) {
            Ok(entries) => for entry in entries {
                let entry = entry?;
                if entry.path().file_stem().and_then(|name| name.to_str()).is_some_and(proposal_key) &&
                    entry.path().extension().is_some_and(|extension| extension == "json") {
                    let proposal = read_record(&entry.path())?;
                    if !proposal.is_null() { proposals.push(proposal); }
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        proposals.sort_by(|left, right| right["createdAt"].as_str().cmp(&left["createdAt"].as_str()));
        let ssh_port = self.projected()?["lifeBoard"].as_str().and_then(|port| port.parse::<u16>().ok());
        let (hosted, ssh) = std::thread::scope(|scope| {
            let hosted = scope.spawn(|| observe(self.runtime.hosted_port));
            let ssh = ssh_port.and_then(observe);
            (hosted.join().ok().flatten(), ssh)
        });
        let (_, now) = timestamp();
        let response = self.run(json!({"origin":self.runtime.origin,"method":request.method,"fields":fields.record(),
            "fieldCount":fields.len(),"now":now,"local":local,"proposals":proposals,"observations":{"hosted":hosted,"ssh":ssh}}))?;
        let write = &response["write"];
        match write["target"].as_str() {
            Some("local") => write_record(&local_path, &write["record"], true)?,
            Some("proposal") => {
                let key = string(&write["key"])?;
                if !proposal_key(key) { return Err(fail("invalid workspace proposal key")); }
                DirBuilder::new().recursive(true).mode(0o700).create(&proposals_path)?;
                write_record(&proposals_path.join(format!("{key}.json")), &write["record"], false)?;
            }
            _ => (),
        }
        self.render(response_status(&response)?, "versions", string(&response["content"])?, fragment)
    }
}

fn proposal_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn observe(port: u16) -> Option<Vec<String>> {
    let origin = format!("http://127.0.0.1:{port}");
    std::thread::scope(|scope| {
        let observations = ["/", "/life-board.css", "/_encounter/browser.mjs"].map(|path| {
            let origin = &origin;
            scope.spawn(move || {
                let result = exchange(origin, path, "GET", &[], None, "2.5").ok()?;
                result.success().then(|| hex::encode(Sha256::digest(result.body)))
            })
        });
        observations.into_iter().map(|thread| thread.join().ok().flatten()).collect()
    })
}
