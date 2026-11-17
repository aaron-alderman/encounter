mod appdev_assurance;
mod appdev_catalogue_excerpts;
mod appdev_host_process;
mod appdev_reload;
mod appdev_lifecycle;
mod appdev_system_lifecycle;
mod appdev_module_activation;
mod workspace_sign_in;
mod workspace_completion_bridge;
mod appdev_mailbox;
mod appdev_performance;
mod appdev_preview;
mod appdev_preview_broker;
mod appdev_release;
mod appdev_route_check;
mod appdev_sweep_journal;
mod appdev_test_grant;
mod appdev_workflow;
mod scheduled_receipt;
mod server_temple_capsule;
mod server_temple_application;
mod server_temple_checkpoint;
mod server_temple_readiness;
mod server_temple_publication;
mod server_temple_transit;
mod release_package;
mod browser_check;
mod decompiler_check;
mod application;
mod package;
mod attachment;
mod browser_host;
mod browser_form;
mod browser_operator;
mod browser_build;
mod browser_release;
mod source_frontend;
mod command;
mod command_sources;
mod certificate_inventory;
mod certificate_renewal;
mod certificate_tls;
mod compat_value;
mod csv;
mod declared_web;
mod directory;
mod file_index;
mod systemd_user_service;
mod front_gate_host;
mod device_edge;
mod device_window;
mod evaluation_surface;
mod evaluation_replay;
mod http;
mod http_client;
mod gateway;
mod google_identity;
mod google_identity_custody;
mod google_identity_migration;
mod hosted_tls_deploy;
mod timesheet_restore;
mod postgres;
mod postgres_provision;
mod hosted_postgres;
mod hosted_capacity;
mod hosted_reconciliation;
mod hosted_private_fs;
mod hosted_production_manifest;
mod hosted_workspace_bootstrap;
mod hosted_workspace_storage;
mod development_receive;
mod hosted_release_identity;
mod hosted_release_inputs;
mod hosted_layer_assembly;
mod platform_import_closure;
mod programme_catalogue_source;
mod production_catalogue_identity;
mod hosted_launch_config;
mod hosted_oidc;
mod hosted_control_access;
mod hosted_http_route;
mod hosted_generation_process;
mod hosted_generation_proxy;
mod hosted_generation_supervisor;
mod hosted_composition;
mod hosted_dependencies;
mod hosted_worker_image;
mod hosted_worker_workspace;
mod hosted_worker_assignment;
mod hosted_worker_container;
mod archive;
mod self_hosted_identity;
mod self_hosted_identity_crypto;
mod self_hosted_identity_provision;
mod self_hosted_production_custody;
mod public_mcp;
mod mcp_authorization;
mod mcp_client;
mod mcp_client_socket;
mod mcp_observation_store;
mod mcp_workspace_access;
mod mcp_project_context;
mod mcp_project_socket;
mod runtime_authority;
mod runtime_authority_client;
mod runtime_grant_audit;
mod runtime_grant_verify;
mod assurance_view;
mod disk_pressure;
mod disk_pressure_host;
mod image;
mod launch;
mod nonce;
mod network_build;
mod network_controller;
mod network_probe;
mod network_transport;
mod operator;
mod ollama;
mod codex_stream;
mod aster_codex;
mod aster_codex_live;
mod websocket;
mod live;
mod process;
mod publication;
mod publication_data;
mod rel;
mod signature;
mod ssh_mcp;
mod peer_host;
mod peer_identity;
mod peer_transport;
mod sqlite;
mod store;
mod surface_image;
mod workspace;
mod x509;

use application::CheckProfile;
use launch::Launch;
use std::{env, path::Path, process::ExitCode};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn fail(message: impl Into<String>) -> Box<dyn std::error::Error> { message.into().into() }

fn execute_config(file: &Path, args: &[String]) -> Result<ExitCode> {
    if !matches!(args, [command] if command == "serve") {
        return Err(fail("expected serve for an image launch configuration"));
    }
    declared_web::serve_launch(Launch::read(file)?)?;
    Ok(ExitCode::SUCCESS)
}

fn execute(args: &[String]) -> Result<ExitCode> {
    match args {
        [flag, file, rest @ ..] if flag == "--config" => execute_config(Path::new(file), rest),
        [flag] if flag == "--version" => {
            println!("encounter {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        [command, flag, root, declaration, arguments @ ..] if command == "run" && flag == "--declaration" =>
            command::run(Path::new(root), declaration, arguments).map(|_| ExitCode::SUCCESS),
        [command, flag, root, declaration, arguments @ ..]
            if command == "run" && matches!(flag.as_str(), "--sources" | "--sources-stdin") => {
            match command::run_sources(Path::new(root), declaration, arguments, flag == "--sources-stdin") {
                Ok(status) => Ok(ExitCode::from(status)),
                Err(error) => {
                    eprintln!("{error}");
                    Ok(ExitCode::from(2))
                }
            }
        }
        [command, flag, root, declaration] if command == "run" && flag == "--stdin" =>
            command::run_stdin(Path::new(root), declaration).map(|_| ExitCode::SUCCESS),
        [command, flag, root, declaration] if command == "run" && flag == "--lines" =>
            command::run_lines(Path::new(root), declaration).map(|_| ExitCode::SUCCESS),
        [command, flag, root, declaration] if command == "test" && flag == "--declaration" =>
            command::test(Path::new(root), declaration).map(|_| ExitCode::SUCCESS),
        [command, capsule] if command == "inspect-server-temple-capsule" =>
            server_temple_capsule::run(Path::new(capsule)).map(|_| ExitCode::SUCCESS),
        [command, config] if command == "server-temple-checkpoint" =>
            server_temple_checkpoint::run(Path::new(config)).map(|_| ExitCode::SUCCESS),
        [command, config] if command == "server-temple-custody" =>
            server_temple_checkpoint::hold(Path::new(config)).map(|_| ExitCode::SUCCESS),
        [command, config] if command == "server-temple-host" =>
            server_temple_checkpoint::host(Path::new(config)).map(|_| ExitCode::SUCCESS),
        [command, config] if command == "server-temple-readiness" =>
            server_temple_readiness::run(Path::new(config)).map(|_| ExitCode::SUCCESS),
        [command, artifact, config, drop_in] if command == "install-server-temple-readiness" =>
            server_temple_readiness::install(Path::new(artifact), Path::new(config), Path::new(drop_in)).map(|_| ExitCode::SUCCESS),
        [command, config] if command == "gateway" =>
            gateway::serve(Path::new(config)).map(|_| ExitCode::SUCCESS),
        [command, port, upstream, origin] if command == "workspace-completion-bridge" =>
            workspace_completion_bridge::serve(port.parse()?, upstream.parse()?, origin).map(|_| ExitCode::SUCCESS),
        [command, port] if command == "workspace-sign-in-presentation" =>
            gateway::serve_workspace_sign_in_presentation(port.parse()?, None).map(|_| ExitCode::SUCCESS),
        [command, port, socket, authority_uid] if command == "workspace-sign-in-presentation" =>
            gateway::serve_workspace_sign_in_presentation(port.parse()?, Some((Path::new(socket), authority_uid.parse()?)))
                .map(|_| ExitCode::SUCCESS),
        [command, origin] if command == "sourcery-workspace" =>
            workspace::terminal_client::run(origin),
        [command, release] if command == "appdev-file-viewer" =>
            workspace::serve_file_index(Path::new(release)).map(|_| ExitCode::SUCCESS),
        [command, release] if command == "appdev-vm-manager" =>
            workspace::serve_vm_manager(Path::new(release)).map(|_| ExitCode::SUCCESS),
        [command, release] if command == "workspace-host" =>
            workspace::serve(Path::new(release), false).map(|_| ExitCode::SUCCESS),
        [command, flag, release] if command == "workspace-host" && flag == "--follow-release" =>
            workspace::serve(Path::new(release), true).map(|_| ExitCode::SUCCESS),
        [command, release, port] if command == "appdev-browser-host" =>
            browser_host::serve_appdev(Path::new(release), port.parse()?, false).map(|_| ExitCode::SUCCESS),
        [command, flag, release, port] if command == "appdev-browser-host" && flag == "--allow-aster-stream" =>
            browser_host::serve_appdev(Path::new(release), port.parse()?, true).map(|_| ExitCode::SUCCESS),
        [command, active, legacy, port] if command == "appdev-work-host" =>
            appdev_workflow::serve_work(Path::new(active), Path::new(legacy), port.parse()?).map(|_| ExitCode::SUCCESS),
        [command, active, config] if command == "appdev-work-gateway" =>
            appdev_workflow::serve_work_gateway(Path::new(active), Path::new(config), None).map(|_| ExitCode::SUCCESS),
        // Installed sweep drivers still use the old positional layout for bundled probes.
        [command, active, marker, config] if command == "appdev-work-gateway" && marker == "/" =>
            appdev_workflow::serve_work_gateway(Path::new(active), Path::new(config), None).map(|_| ExitCode::SUCCESS),
        [command, active, config, flag, standalone] if command == "appdev-work-gateway" && flag == "--standalone-policy" =>
            appdev_workflow::serve_work_gateway(Path::new(active), Path::new(config), Some(Path::new(standalone))).map(|_| ExitCode::SUCCESS),
        [command, active, config] if command == "appdev-workgarden" =>
            appdev_workflow::serve_workgarden(Path::new(active), Path::new(config)).map(|_| ExitCode::SUCCESS),
        [command, active, config] if matches!(command.as_str(), "appdev-shop-host" | "appdev-shop-gateway") =>
            appdev_workflow::serve_shop(Path::new(active), Path::new(config), command == "appdev-shop-gateway").map(|_| ExitCode::SUCCESS),
        [command, release, config] if command == "appdev-shop-image" =>
            appdev_workflow::serve_shop_image(Path::new(release), Path::new(config)).map(|_| ExitCode::SUCCESS),
        [command, config, sockets] if command == "device-edge" =>
            device_edge::serve(Path::new(config), Path::new(sockets)).map(|_| ExitCode::SUCCESS),
        [command, config, profile, renderer] if command == "device-window" =>
            device_window::open(Path::new(config), Path::new(profile), Path::new(renderer)).map(|_| ExitCode::SUCCESS),
        [command, root, declaration, port] if command == "directory" =>
            directory::serve(Path::new(root), declaration, port.parse()?).map(|_| ExitCode::SUCCESS),
        [command, flag, config, cache] if command == "file-index" && flag == "--refresh" =>
            file_index::run(Path::new(config), Path::new(cache), None).map(|_| ExitCode::SUCCESS),
        [command, flag, config, cache, seconds] if command == "file-index" && flag == "--watch" =>
            file_index::run(Path::new(config), Path::new(cache), Some(seconds.parse()?)).map(|_| ExitCode::SUCCESS),
        [command, flag, config, cache, socket] if command == "file-index" && flag == "--serve" =>
            file_index::serve(Path::new(config), Path::new(cache), Path::new(socket)).map(|_| ExitCode::SUCCESS),
        [command, flag, config, assets, port] if command == "browser-host" && flag == "--surface" =>
            browser_host::serve_surface(Path::new(config), Path::new(assets), port.parse()?).map(|_| ExitCode::SUCCESS),
        [command, flag, root, pin, port] if command == "browser-host" && flag == "--release" =>
            browser_host::serve_release(Path::new(root), pin, port.parse()?).map(|_| ExitCode::SUCCESS),
        [command, flag, root, declaration, assets, store, port]
            if command == "browser-host" && flag == "--form-store" =>
            browser_host::serve_form(Path::new(root), declaration, Path::new(assets), Path::new(store), port.parse()?)
                .map(|_| ExitCode::SUCCESS),
        [command, flag, root, declaration, assets, store, operators, port]
            if command == "browser-host" && flag == "--durable" =>
            browser_host::serve_durable(Path::new(root), declaration, Path::new(assets),
                Path::new(store), Path::new(operators), port.parse()?).map(|_| ExitCode::SUCCESS),
        [command, flag, root, declaration, assets, store, operators, sockets, port]
            if command == "browser-host" && flag == "--device" =>
            browser_host::serve_device(Path::new(root), declaration, Path::new(assets), Path::new(store),
                Path::new(operators), Path::new(sockets), port.parse()?).map(|_| ExitCode::SUCCESS),
        [command, flag, root, declaration, assets, store, operators, peers, port]
            if command == "browser-host" && matches!(flag.as_str(), "--temple" | "--temple-window") =>
            browser_host::serve_temple(Path::new(root), declaration, Path::new(assets),
                Path::new(store), Path::new(operators), Path::new(peers), port.parse()?, flag == "--temple-window", "").map(|_| ExitCode::SUCCESS),
        [command, flag, root, declaration, assets, store, operators, peers, port, mount]
            if command == "browser-host" && flag == "--temple-window" =>
            browser_host::serve_temple(Path::new(root), declaration, Path::new(assets),
                Path::new(store), Path::new(operators), Path::new(peers), port.parse()?, true, mount).map(|_| ExitCode::SUCCESS),
        [command, flag, root, declaration, assets, port] if command == "browser-host" && flag == "--allow-aster-stream" =>
            browser_host::serve(Path::new(root), declaration, Path::new(assets), port.parse()?, true)
                .map(|_| ExitCode::SUCCESS),
        [command, root, declaration, assets, port] if command == "browser-host" =>
            browser_host::serve(Path::new(root), declaration, Path::new(assets), port.parse()?, false).map(|_| ExitCode::SUCCESS),
        [command, root, port] if command == "publication" =>
            publication::serve(Path::new(root), port.parse()?).map(|_| ExitCode::SUCCESS),
        [command, flag, root, manifest, pin, port] if command == "publication" && flag == "--pinned" =>
            publication::serve_pinned(Path::new(root), Path::new(manifest), pin, port.parse()?).map(|_| ExitCode::SUCCESS),
        [command, flag, root, declaration, libraries, output] if command == "build" && flag == "--browser" => {
            browser_build::build(Path::new(root), declaration, Path::new(libraries), Path::new(output))?;
            Ok(ExitCode::SUCCESS)
        }
        [command, root, declaration, output] if command == "build" => {
            println!("{}", image::build(Path::new(root), declaration, Path::new(output))?);
            Ok(ExitCode::SUCCESS)
        }
        [command, flag, file, pin, directory, port]
            if command == "serve" && flag == "--image" =>
            declared_web::serve_image(image::load(Path::new(file), pin)?, Path::new(directory), port.parse()?, None, None, live::Model::Off, false)
                .map(|_| ExitCode::SUCCESS),
        [command, flag, root, declaration, directory, port]
            if command == "serve" && flag == "--declaration" =>
            declared_web::serve(Path::new(root), declaration, Path::new(directory), port.parse()?)
                .map(|_| ExitCode::SUCCESS),
        [command, flag, root, declaration] if command == "check" && matches!(flag.as_str(), "--browser" | "--browser-durable" | "--browser-temple") => {
            let profile = match flag.as_str() {
                "--browser-durable" => CheckProfile::DurableBrowser,
                "--browser-temple" => CheckProfile::TempleBrowser,
                _ => CheckProfile::Browser,
            };
            let admitted = application::Application::load(Path::new(root), declaration)?.check(profile)?;
            Ok(if admitted { ExitCode::SUCCESS } else { ExitCode::from(2) })
        }
        [command, mode, target, current, candidate] if command == "appdev-module-activation" => {
            appdev_module_activation::run(mode, target, Path::new(current), Path::new(candidate))?;
            Ok(ExitCode::SUCCESS)
        }
        [command, policy, current, candidate] if command == "appdev-system-activation-plan" => {
            let report = appdev_system_lifecycle::plan(Path::new(policy), Path::new(current), Path::new(candidate))?;
            println!("{report}");
            Ok(ExitCode::SUCCESS)
        }
        [command, policy, inventory, current, candidate] if command == "appdev-release-impact" => {
            let report = appdev_lifecycle::report(Path::new(policy), Path::new(inventory),
                Path::new(current), Path::new(candidate))?;
            println!("{report}");
            Ok(ExitCode::SUCCESS)
        }
        [command, root] if command == "appdev-release-fingerprint" => {
            println!("{}", appdev_assurance::fingerprint(Path::new(root))?);
            Ok(ExitCode::SUCCESS)
        }
        [command, root] if command == "appdev-publish-catalogue-excerpts" =>
            appdev_catalogue_excerpts::run(Path::new(root)).map(|_| ExitCode::SUCCESS),
        [command, app, sources, package, output] if command == "appdev-stage-browser-wasm" =>
            appdev_workflow::stage_browser_wasm(Path::new(app), Path::new(sources), Path::new(package), Path::new(output), false)
                .map(|_| ExitCode::SUCCESS),
        [command, refresh, app, sources, package, output] if command == "appdev-stage-browser-wasm" && refresh == "--refresh-runtime" =>
            appdev_workflow::stage_browser_wasm(Path::new(app), Path::new(sources), Path::new(package), Path::new(output), true)
                .map(|_| ExitCode::SUCCESS),
        [command, root] if command == "check-appdev-release" =>
            appdev_release::check(Path::new(root)).map(|_| ExitCode::SUCCESS),
        [command, app, phase] if command == "appdev-check-workspace-routes" =>
            appdev_route_check::run(Path::new(app), phase).map(|_| ExitCode::SUCCESS),
        [command, root] if command == "appdev-deploy-system" =>
            appdev_workflow::deploy_verified(Path::new(root)).map(|_| ExitCode::SUCCESS),
        [command, app] if command == "appdev-capacity-sweep" =>
            appdev_performance::capacity_sweep(Path::new(app), None).map(|_| ExitCode::SUCCESS),
        [command, app, option, candidate] if command == "appdev-capacity-sweep" && option == "--candidate" =>
            appdev_performance::capacity_sweep(Path::new(app), Some(Path::new(candidate))).map(|_| ExitCode::SUCCESS),
        [command, app] if command == "appdev-launch-sweep" =>
            appdev_performance::launch_sweep(Path::new(app)).map(|_| ExitCode::SUCCESS),
        [command, app, socket] if command == "appdev-performance-mailbox" =>
            appdev_mailbox::serve(Path::new(app), Path::new(socket)).map(|_| ExitCode::SUCCESS),
        [command, app, socket, scenario] if command == "appdev-performance-mailbox-fixture" =>
            appdev_mailbox::serve_fixture(Path::new(app), Path::new(socket), scenario).map(|_| ExitCode::SUCCESS),
        [command, directory] if command == "appdev-publish-front-gate-receipt" =>
            scheduled_receipt::front_gate(Path::new(directory)).map(|_| ExitCode::SUCCESS),
        [command, source, version, binary, output, pin @ ..]
            if matches!(command.as_str(), "package-release" | "package-platform-release") && pin.len() <= 1 =>
            release_package::build(if command == "package-release" { release_package::ReleaseLayout::Aggregate }
                else { release_package::ReleaseLayout::Platform }, Path::new(source), version, Path::new(binary), Path::new(output),
                pin.first().map(String::as_str)).map(|_| ExitCode::SUCCESS),
        [command, runtime, intake] if command == "stage-temple3" =>
            release_package::stage_temple3(Path::new(runtime), Path::new(intake)).map(|_| ExitCode::SUCCESS),
        [command, projects, app @ ..] if command == "check-guard-pins" && app.len() <= 1 =>
            release_package::check_guard_pins(Path::new(projects), app.first().map(String::as_str)).map(|_| ExitCode::SUCCESS),
        [command, projects, version, candidate, compilers] if command == "promote-guards" =>
            release_package::promote_guards(Path::new(projects), version, Path::new(candidate), Path::new(compilers))
                .map(|_| ExitCode::SUCCESS),
        [command, projects, app, version, binary, output, pin @ ..] if command == "build-guarded-image" && pin.len() <= 1 =>
            release_package::build_guarded_image(Path::new(projects), app, version, Path::new(binary), Path::new(output),
                pin.first().map(String::as_str)).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "appdev-formation-grant" =>
            appdev_test_grant::update(operation).map(|_| ExitCode::SUCCESS),
        [command, app, expected] if command == "appdev-live-formation" =>
            appdev_workflow::check_live_formation(Path::new(app), Path::new(expected)).map(|_| ExitCode::SUCCESS),
        [command, app, mode, port, config, pin] if command == "appdev-decompiler-check" && mode == "mount" =>
            decompiler_check::check_mount(Path::new(app), port, Path::new(config), pin).map(|_| ExitCode::SUCCESS),
        [command, app, mode, port] if command == "appdev-decompiler-check" && mode == "paging" =>
            decompiler_check::check_paging(Path::new(app), port).map(|_| ExitCode::SUCCESS),
        [command, app, mode] if command == "appdev-decompiler-check" && mode == "mount-document" =>
            decompiler_check::mount_document(Path::new(app)).map(|_| ExitCode::SUCCESS),
        [command, app, operation, requested] if command == "appdev-release" =>
            appdev_workflow::release(Path::new(app), operation, Path::new(requested)).map(|_| ExitCode::SUCCESS),
        [command, _, _, _, _, ..] if command == "appdev-release" =>
            Err(fail("AppDev release operations take one package or preview declaration")),
        [command, app, listener, gateway, preview, steward] if command == "appdev-preview-broker" =>
            appdev_preview_broker::serve(Path::new(app), listener, gateway, preview, steward).map(|_| ExitCode::SUCCESS),
        [command, release, previous] if command == "appdev-activate-home" =>
            appdev_workflow::activate(Path::new(release), Path::new(previous)).map(|_| ExitCode::SUCCESS),
        [command, release, previous] if command == "appdev-activate-system-lifecycle" =>
            appdev_workflow::activate_system_lifecycle(Path::new(release), Path::new(previous)).map(|_| ExitCode::SUCCESS),
        [command, release, previous] if command == "appdev-activate-system" =>
            appdev_workflow::activate_system(Path::new(release), Path::new(previous)).map(|_| ExitCode::SUCCESS),
        [command, source, seed, destination] if command == "appdev-stage-aster" =>
            appdev_workflow::stage_aster(Path::new(source), Path::new(seed), Path::new(destination)).map(|_| ExitCode::SUCCESS),
        [command, root, declaration, port] if command == "front-gate-host" =>
            front_gate_host::serve(Path::new(root), declaration, port.parse()?).map(|_| ExitCode::SUCCESS),
        [command, port, schema, schema_pin, policy, policy_pin, socket, uid] if command == "public-mcp-read" =>
            public_mcp::serve(port.parse()?,
                mcp_authorization::load(Path::new(schema), schema_pin, Path::new(policy), policy_pin, None)?,
                mcp_project_socket::Client::load(Path::new(socket), uid.parse()?, schema_pin, policy_pin)?)
                .map(|_| ExitCode::SUCCESS),
        [command, schema, schema_pin, policy, policy_pin, rest @ ..]
            if command == "hosted-mcp-authorization" && rest.len() <= 1 =>
            mcp_authorization::run(Path::new(schema), schema_pin, Path::new(policy), policy_pin,
                rest.first().map(|port| port.parse()).transpose()?).map(|_| ExitCode::SUCCESS),
        [command, clients, clients_pin, hosts, hosts_pin, schema, schema_pin, policy, policy_pin]
            if command == "hosted-mcp-client" =>
            mcp_client::run(Path::new(clients), clients_pin, Path::new(hosts), hosts_pin,
                mcp_authorization::load(Path::new(schema), schema_pin, Path::new(policy), policy_pin, None)?)
                .map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-mcp-metadata-settings" =>
            mcp_client::metadata_settings().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-mcp-metadata-resolve" =>
            mcp_client::resolve_metadata().map(|_| ExitCode::SUCCESS),
        [command, operation, rest @ ..] if command == "hosted-mcp-client" && operation == "serve" =>
            mcp_client_socket::serve(rest).map(|_| ExitCode::SUCCESS),
        [command, operation, rest @ ..] if command == "hosted-mcp-client" && operation == "lookup" =>
            mcp_client_socket::lookup(rest).map(|_| ExitCode::SUCCESS),
        [command, rest @ ..] if command == "hosted-mcp-workspace-access" =>
            mcp_workspace_access::run(rest).map(|_| ExitCode::SUCCESS),
        [command, operation, rest @ ..] if command == "hosted-mcp-project" && operation == "serve" =>
            mcp_project_socket::serve(rest).map(|_| ExitCode::SUCCESS),
        [command, rest @ ..] if command == "hosted-mcp-project" =>
            mcp_project_context::run(rest).map(|_| ExitCode::SUCCESS),
        [command] if command == "runtime-authority" =>
            runtime_authority::serve().map(|_| ExitCode::SUCCESS),
        [command, socket] if command == "runtime-authority-readiness" =>
            runtime_authority_client::run(runtime_authority_client::Operation::Readiness, Path::new(socket)).map(|_| ExitCode::SUCCESS),
        [command, socket] if command == "runtime-authority-sign-grant" =>
            runtime_authority_client::run(runtime_authority_client::Operation::SignGrant, Path::new(socket)).map(|_| ExitCode::SUCCESS),
        [command, socket] if command == "runtime-authority-workload" =>
            runtime_authority_client::run(runtime_authority_client::Operation::Workload, Path::new(socket)).map(|_| ExitCode::SUCCESS),
        [command] if command == "google-identity-custody" =>
            google_identity_custody::run().map(|_| ExitCode::SUCCESS),
        [command] if command == "google-identity" =>
            google_identity::serve().map(|_| ExitCode::SUCCESS),
        [command] if command == "google-identity-migrate-custody" =>
            google_identity_migration::run().map(|_| ExitCode::SUCCESS),
        [command] if command == "self-hosted-identity" =>
            self_hosted_identity::serve().map(|_| ExitCode::SUCCESS),
        [command, directory] if command == "self-hosted-identity-provision" =>
            self_hosted_identity_provision::from_stdin(Path::new(directory)).map(|_| ExitCode::SUCCESS),
        [command] if command == "self-hosted-identity-prompt" =>
            self_hosted_identity_provision::prompt().map(|_| ExitCode::SUCCESS),
        [command, directory] if command == "self-hosted-production-custody" =>
            self_hosted_production_custody::run(Path::new(directory)).map(|_| ExitCode::SUCCESS),
        [command, archive, digest, before, after, target] if command == "rehearse-timesheet-restore" =>
            timesheet_restore::run(Path::new(archive), digest, Path::new(before), Path::new(after), Path::new(target)).map(|_| ExitCode::SUCCESS),
        [command] if command == "provision-self-hosted-postgres" =>
            postgres_provision::run().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-production-manifest" =>
            hosted_production_manifest::run().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-operations-release-proposal" =>
            hosted_production_manifest::check_release_proposal().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-operations-release-coordinate" =>
            hosted_production_manifest::coordinate_release().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-operations-release-assess" =>
            hosted_production_manifest::assess_release().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-operations-release-artifact" =>
            hosted_production_manifest::create_release_artifact().map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-operations-retained-release" =>
            hosted_production_manifest::check_retained_release(operation).map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-oauth-client-registry" =>
            mcp_client::read_registered_clients().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-operations-approver" =>
            hosted_production_manifest::operations_approver().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-catalogue-publication-authorize" =>
            hosted_production_manifest::catalogue_authorize().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-runtime-grant-verify" =>
            runtime_grant_verify::run(false).map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-runtime-grant-resolve" =>
            runtime_grant_verify::run(true).map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-runtime-grant-issue" =>
            runtime_grant_verify::issue().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-runtime-grant-resolve-current-binding" =>
            runtime_grant_verify::resolve_current_binding().map(|_| ExitCode::SUCCESS),
        [command, arguments @ ..] if command == "hosted-workspace-bootstrap" =>
            hosted_workspace_bootstrap::run(arguments).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-workspace-storage" =>
            hosted_workspace_storage::run(operation).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-private-storage" =>
            hosted_reconciliation::storage(operation).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-reconciliation-decision" =>
            hosted_reconciliation::decision(operation).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-capacity-postgres" =>
            hosted_capacity::postgres(operation).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-capacity-memory" =>
            hosted_capacity::memory(operation).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-capacity-decision" =>
            hosted_capacity::decision(operation).map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-postgres-config" =>
            hosted_postgres::configuration().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-postgres-readiness" =>
            hosted_postgres::readiness().map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "runtime-grant-audit-memory" =>
            runtime_grant_audit::memory(match operation.as_str() {
                "validate" => runtime_grant_audit::Operation::Validate,
                "snapshot" => runtime_grant_audit::Operation::Snapshot,
                "append" => runtime_grant_audit::Operation::Append,
                _ => return Err(fail("Unsupported memory audit operation")),
            }).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "runtime-grant-audit-postgres" =>
            runtime_grant_audit::postgres(match operation.as_str() {
                "snapshot" => runtime_grant_audit::Operation::Snapshot,
                "append" => runtime_grant_audit::Operation::Append,
                _ => return Err(fail("Unsupported PostgreSQL audit operation")),
            }).map(|_| ExitCode::SUCCESS),
        [command] if command == "runtime-grant-audit-retention" =>
            runtime_grant_audit::retention().map(|_| ExitCode::SUCCESS),
        [command, phase] if command == "provision-self-hosted-postgres-worker" =>
            postgres_provision::worker(phase).map(|_| ExitCode::SUCCESS),
        [command, root, expected @ ..] if command == "hosted-temple-freeze" && expected.len() <= 1 =>
            hosted_release_identity::temple(Path::new(root), expected.first().map(String::as_str)).map(|_| ExitCode::SUCCESS),
        [command, root, state, paths @ ..] if command == "hosted-source-tree" && !paths.is_empty() =>
            hosted_release_identity::source(Path::new(root), Path::new(state), paths).map(|_| ExitCode::SUCCESS),
        [command, root, state, paths @ ..] if command == "hosted-audit-execution-candidates" && !paths.is_empty() =>
            hosted_release_identity::execution_candidates(Path::new(root), Path::new(state), paths).map(|_| ExitCode::SUCCESS),
        [command, root, state, paths @ ..] if command == "development-source-tree" && !paths.is_empty() =>
            hosted_release_identity::development_source(Path::new(root), Path::new(state), paths).map(|_| ExitCode::SUCCESS),
        [command, root] if command == "development-repository-status" =>
            development_receive::inspect_checkout(Path::new(root)).map(|_| ExitCode::SUCCESS),
        [command, root] if command == "development-historical-source" =>
            development_receive::historical_source(Path::new(root)).map(|_| ExitCode::SUCCESS),
        [command, source, release] if command == "hosted-generation-identity" =>
            hosted_release_identity::generation(source, release).map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-production-supervisor" =>
            hosted_generation_supervisor::run().map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-http-route" =>
            hosted_http_route::run(operation).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-control-access" =>
            hosted_control_access::run(operation).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-oidc-decision" =>
            hosted_oidc::run(operation).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "ssh-mcp-assertion" =>
            ssh_mcp::run(operation).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-launch-config" =>
            hosted_launch_config::run(operation).map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-supervisor-config" =>
            hosted_release_identity::supervisor_config().map(|_| ExitCode::SUCCESS),
        [command, digest] if command == "build-self-hosted-worker-image" =>
            hosted_worker_image::run(digest).map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-worker-image-digest" =>
            hosted_worker_image::validate_digest().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-worker-image-admission" =>
            hosted_worker_image::validate_admission().map(|_| ExitCode::SUCCESS),
        [command, file, image, uid] if command == "hosted-worker-image-admission-file" =>
            hosted_worker_image::read_admission(Path::new(file), image, uid.parse()?).map(|_| ExitCode::SUCCESS),
        [command, digest, socket] if command == "hosted-container-readiness" =>
            hosted_worker_container::readiness(digest, socket).map(|_| ExitCode::SUCCESS),
        [command, request] if command == "hosted-container-plan" =>
            hosted_worker_container::plan(request).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-container-dispatch" =>
            hosted_worker_container::dispatch_policy(operation).map(|_| ExitCode::SUCCESS),
        [command, request] if command == "hosted-container-run" =>
            hosted_worker_container::run(request).map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-worker-assignment-config" =>
            hosted_worker_assignment::config().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-worker-assignment-issue" =>
            hosted_worker_assignment::issue().map(|_| ExitCode::SUCCESS),
        [command, root, tenant, app, project, workspace, region, namespace] if command == "hosted-worker-project" =>
            hosted_worker_workspace::run(Path::new(root), serde_json::json!({
                "tenantId": tenant, "appId": app, "projectId": project, "workspaceId": workspace,
                "region": region, "storageNamespace": namespace,
            })).map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-worker-launch" =>
            hosted_release_identity::worker_decision(hosted_release_identity::WorkerDecision::Launch).map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-worker-release" =>
            hosted_release_identity::worker_release().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-worker-basis" =>
            hosted_release_identity::worker_decision(hosted_release_identity::WorkerDecision::Basis).map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-worker-identity" =>
            hosted_release_identity::worker_decision(hosted_release_identity::WorkerDecision::Identity).map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-cutover-decision" =>
            hosted_release_identity::worker_decision(hosted_release_identity::WorkerDecision::Cutover).map(|_| ExitCode::SUCCESS),
        [command, expected_host, observed_host, port, observed_generation, source, release, generation, timeout]
            if command == "hosted-generation-readiness" =>
            hosted_release_identity::generation_readiness(hosted_release_identity::GenerationProbe {
                expected_host, observed_host, observed_port: port, observed_generation,
                source, release, generation, timeout_ms: timeout.parse()?,
            }).map(|_| ExitCode::SUCCESS),
        [command, root, pointer] if command == "hosted-admission-pointer" =>
            hosted_release_identity::admission_pointer(Path::new(root), Path::new(pointer)).map(|_| ExitCode::SUCCESS),
        [command, root, pointer] if command == "hosted-admission-artifact" =>
            hosted_release_identity::admission_artifact(Path::new(root), Path::new(pointer)).map(|_| ExitCode::SUCCESS),
        [command, active, candidate, accepted, rejected @ ..] if command == "hosted-reload-decision" && rejected.len() <= 1 =>
            hosted_release_identity::reload(active.parse()?, candidate, accepted, rejected.first().map(String::as_str)).map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-verify-platform-import-closure" =>
            platform_import_closure::run().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-audit-programme-completion" =>
            platform_import_closure::audit_programme().map(|_| ExitCode::SUCCESS),
        [command] if command == "hosted-read-knowledge-catalogue" =>
            platform_import_closure::read_catalogue().map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-build-knowledge-catalogue" =>
            platform_import_closure::build_catalogue(operation).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-knowledge-catalogue-integration" =>
            platform_import_closure::catalogue_integration(operation).map(|_| ExitCode::SUCCESS),
        [command, operation, root] if command == "hosted-programme-catalogue-source" =>
            programme_catalogue_source::run(operation, Path::new(root)).map(|_| ExitCode::SUCCESS),
        [command, file] if command == "hosted-production-catalogue-identity" =>
            production_catalogue_identity::run(Path::new(file)).map(|_| ExitCode::SUCCESS),
        [command, operation] if command == "hosted-mcp-observation-ledger" =>
            platform_import_closure::observation_ledger(operation).map(|_| ExitCode::SUCCESS),
        [command, operation, file] if command == "hosted-mcp-observation-store" =>
            mcp_observation_store::run(operation, Path::new(file)).map(|_| ExitCode::SUCCESS),
        [command, root, layout] if command == "hosted-verify-platform-payload" =>
            hosted_layer_assembly::verify_payload(root, layout).map(|_| ExitCode::SUCCESS),
        [command, arguments @ ..] if command == "hosted-compose-layers" =>
            hosted_layer_assembly::run(arguments).map(|_| ExitCode::SUCCESS),
        [command, root] if command == "hosted-prepare-production-release" =>
            hosted_release_inputs::run(Path::new(root)).map(|_| ExitCode::SUCCESS),
        [command, root, expected] if command == "stage-hosted-release-runtime" =>
            hosted_release_identity::stage_runtime(Path::new(root), expected).map(|_| ExitCode::SUCCESS),
        [command, archive, pin] if command == "hosted-temple-archive-check" =>
            hosted_release_identity::check_archive(Path::new(archive), pin).map(|_| ExitCode::SUCCESS),
        [command, archive, pin, tree, target] if command == "hosted-install-temple" =>
            hosted_release_identity::install_temple(Path::new(archive), pin, tree, Path::new(target)).map(|_| ExitCode::SUCCESS),
        [command, root] if command == "hosted-populate-dependencies" =>
            hosted_dependencies::run(Path::new(root)).map(|_| ExitCode::SUCCESS),
        [command, root, store] if command == "hosted-audit-dependencies" =>
            hosted_composition::audit(Path::new(root), Path::new(store)).map(|_| ExitCode::SUCCESS),
        [command, root, archive_file, archive, tree, evidence, store, runtime_version, abi] if command == "hosted-compose-release" =>
            hosted_composition::compose(hosted_composition::Request { root: Path::new(root), archive_file: Path::new(archive_file),
                archive, tree, evidence: Path::new(evidence), store: Path::new(store), runtime_version, abi }).map(|_| ExitCode::SUCCESS),
        [command, root, workspace, port, admission] if command == "aster-codex" =>
            aster_codex::serve(Path::new(root), Path::new(workspace), port.parse()?, Path::new(admission)).map(|_| ExitCode::SUCCESS),
        [command, root, port] if command == "assurance-view" =>
            assurance_view::serve(Path::new(root), port.parse()?).map(|_| ExitCode::SUCCESS),
        [command, observations] if command == "disk-pressure-assess" =>
            disk_pressure::run(Path::new(observations)).map(|_| ExitCode::SUCCESS),
        [command, policy] if command == "disk-pressure-scan" =>
            disk_pressure_host::run(Path::new(policy), false).map(|_| ExitCode::SUCCESS),
        [command, policy] if command == "disk-pressure-publish" =>
            disk_pressure_host::run(Path::new(policy), true).map(|_| ExitCode::SUCCESS),
        [command, root, credentials, port] if command == "certificate-inventory" =>
            certificate_inventory::serve(Path::new(root), Path::new(credentials), port.parse()?).map(|_| ExitCode::SUCCESS),
        [command, root, port] if command == "evaluation-surface" =>
            evaluation_surface::serve(Path::new(root), port.parse()?, None).map(|_| ExitCode::SUCCESS),
        [command, root, port, flag, pin] if command == "evaluation-surface" && flag == "--mount-pin" =>
            evaluation_surface::serve(Path::new(root), port.parse()?, Some(pin)).map(|_| ExitCode::SUCCESS),
        [command, root, directory, port, nginx, tls_port, unit, chain @ ..] if command == "certificate-renewal" && chain.len() <= 1 =>
            certificate_renewal::serve(Path::new(root), Path::new(directory), port.parse()?, Path::new(nginx),
                tls_port.parse()?, unit, chain.first().map(String::as_str)).map(|_| ExitCode::SUCCESS),
        [command, root, managed, output] if command == "build-network-release" =>
            network_build::build(Path::new(root), Path::new(managed), Path::new(output)).map(|_| ExitCode::SUCCESS),
        [command, root, settings] if command == "network-controller" =>
            network_controller::serve(Path::new(root), Path::new(settings)).map(|_| ExitCode::SUCCESS),
        [command, root] if command == "check-package" =>
            package::check(Path::new(root)).map(|_| ExitCode::SUCCESS),
        [command, root, declaration] if command == "check" => {
            let admitted = application::Application::load(Path::new(root), declaration)?.check(CheckProfile::Application)?;
            Ok(if admitted { ExitCode::SUCCESS } else { ExitCode::from(2) })
        }
        _ => Err(fail(concat!(
            "usage: encounter --version | encounter --config FILE serve",
            " | encounter inspect-server-temple-capsule FILE",
            " | encounter server-temple-checkpoint CONFIG",
            " | encounter server-temple-custody CONFIG",
            " | encounter server-temple-host CONFIG",
            " | encounter server-temple-readiness CONFIG",
            " | encounter install-server-temple-readiness ARTIFACT CONFIG DROP_IN",
            " | encounter run --declaration APP_ROOT DECLARATION [ARG ...]",
            " | encounter run --stdin APP_ROOT DECLARATION",
            " | encounter run --lines APP_ROOT DECLARATION",
            " | encounter run --sources APP_ROOT DECLARATION [ARG ...]",
            " | encounter run --sources-stdin APP_ROOT DECLARATION [ARG ...]",
            " | encounter test --declaration APP_ROOT DECLARATION",
            " | encounter serve --declaration APP_ROOT DECLARATION STORE PORT",
            " | encounter build APP_ROOT DECLARATION OUTPUT",
            " | encounter build --browser APP_ROOT DECLARATION LIBRARIES OUTPUT",
            " | encounter gateway CONFIG",
            " | encounter public-mcp-read PORT SCHEMA SHA256 POLICY SHA256 PROJECT_SOCKET PROJECT_UID",
            " | encounter hosted-mcp-authorization SCHEMA SHA256 POLICY SHA256 [LOOPBACK_PORT]",
            " | encounter hosted-mcp-client CLIENTS SHA256 HOSTS SHA256 SCHEMA SHA256 POLICY SHA256",
            " | encounter hosted-mcp-client serve SOCKET CONSUMER_UID CLIENTS SHA256 HOSTS SHA256 SCHEMA SHA256 POLICY SHA256",
            " | encounter hosted-mcp-client lookup SOCKET RESOLVER_UID CLIENTS_SHA256 HOSTS_SHA256 SCHEMA_SHA256 POLICY_SHA256",
            " | encounter hosted-mcp-workspace-access SOCKET PORT DATABASE ROLE SCHEMA SHA256 POLICY SHA256 TENANT APP PROJECT WORKSPACE",
            " | encounter hosted-mcp-project open KEY SOCKET PORT DATABASE ROLE SCHEMA SHA256 POLICY SHA256 TENANT APP PROJECT WORKSPACE",
            " | encounter hosted-mcp-project resolve KEY SOCKET PORT DATABASE ROLE SCHEMA SHA256 POLICY SHA256",
            " | encounter hosted-mcp-project tool KEY SOCKET PORT DATABASE ROLE SCHEMA SHA256 POLICY SHA256",
            " | encounter hosted-mcp-project serve SOCKET GATEWAY_UID KEY DATABASE_SOCKET PORT DATABASE ROLE SCHEMA SHA256 POLICY SHA256",
            " | encounter runtime-authority",
            " | encounter google-identity-custody",
            " | encounter google-identity",
            " | encounter google-identity-migrate-custody",
            " | encounter self-hosted-identity",
            " | encounter self-hosted-identity-provision DIRECTORY",
            " | encounter self-hosted-identity-prompt",
            " | encounter self-hosted-production-custody DIRECTORY",
            " | encounter rehearse-timesheet-restore ARCHIVE EXPECTED_SHA256 BEFORE_MANIFEST AFTER_MANIFEST TARGET",
            " | encounter provision-self-hosted-postgres",
            " | encounter hosted-production-supervisor",
            " | encounter hosted-workspace-bootstrap --authorization-evidence-file FILE [--manifest FILE] [--execute PLAN_SHA256]",
            " | encounter hosted-postgres-config | encounter hosted-postgres-readiness",
            " | encounter runtime-grant-audit-memory {validate|snapshot|append} | encounter runtime-grant-audit-postgres {snapshot|append}",
            " | encounter runtime-grant-audit-retention",
            " | encounter hosted-temple-freeze ROOT [EXPECTED_SHA256]",
            " | encounter hosted-source-tree ROOT STATE_ROOT SOURCE_PATH...",
            " | encounter hosted-audit-execution-candidates ROOT STATE_ROOT SOURCE_PATH...",
            " | encounter hosted-generation-identity SOURCE_SHA256 POINTER_SHA256",
            " | encounter hosted-worker-launch | encounter hosted-worker-basis | encounter hosted-worker-identity",
            " | encounter hosted-worker-release",
            " | encounter build-self-hosted-worker-image sha256:BASE_IMAGE",
            " | encounter hosted-worker-image-digest | encounter hosted-worker-image-admission | encounter hosted-worker-image-admission-file FILE IMAGE UID",
            " | encounter hosted-container-readiness IMAGE SOCKET | encounter hosted-container-plan REQUEST | encounter hosted-container-run REQUEST",
            " | encounter hosted-worker-assignment-config | encounter hosted-worker-assignment-issue",
            " | encounter runtime-authority-readiness SOCKET | encounter runtime-authority-sign-grant SOCKET | encounter runtime-authority-workload SOCKET",
            " | encounter hosted-worker-project ROOT TENANT APP PROJECT WORKSPACE REGION NAMESPACE",
            " | encounter hosted-supervisor-config",
            " | encounter hosted-generation-readiness EXPECTED_HOST OBSERVED_HOST PORT OBSERVED_GENERATION SOURCE_SHA256 POINTER_SHA256 GENERATION_SHA256 TIMEOUT_MS",
            " | encounter hosted-admission-pointer RELEASE_ROOT POINTER_FILE",
            " | encounter hosted-admission-artifact RELEASE_ROOT POINTER_FILE",
            " | encounter hosted-reload-decision ACTIVE CANDIDATE_SHA256 ACCEPTED_SHA256 [REJECTED_SHA256]",
            " | encounter hosted-cutover-decision",
            " | encounter hosted-compose-layers [--source-clean] PLATFORM CAPABILITIES APPLICATIONS TARGET [CORE]",
            " | encounter hosted-verify-platform-payload ROOT sdk|assembled",
            " | encounter hosted-audit-programme-completion",
            " | encounter hosted-read-knowledge-catalogue",
            " | encounter hosted-build-knowledge-catalogue entry|create|programme-entries|coverage",
            " | encounter hosted-knowledge-catalogue-integration contract|readiness|hook-evidence|production",
            " | encounter hosted-programme-catalogue-source production|integrated ROOT",
            " | encounter hosted-production-catalogue-identity FILE",
            " | encounter hosted-mcp-observation-ledger empty|verify|append|summarize|retention-policy",
            " | encounter hosted-mcp-observation-store load|initialize|retain FILE",
            " | encounter hosted-prepare-production-release RELEASE_ROOT",
            " | encounter stage-hosted-release-runtime RELEASE_ROOT EXPECTED_SHA256",
            " | encounter hosted-temple-archive-check ARCHIVE EXPECTED_SHA256",
            " | encounter hosted-install-temple ARCHIVE ARCHIVE_SHA256 TREE_SHA256 TARGET",
            " | encounter hosted-compose-release RELEASE_ROOT TEMPLE_ARCHIVE ARCHIVE_SHA256 TREE_SHA256 RELEASE_EVIDENCE_INPUT CLOSURE_ROOT NODE_VERSION NODE_ABI",
            " | encounter hosted-audit-dependencies RELEASE_ROOT CLOSURE_ROOT",
            " | encounter assurance-view REPORT_DIRECTORY PORT",
            " | encounter aster-codex CODEX_HOME WORKSPACE PORT ADMISSION_FILE",
            " | encounter disk-pressure-assess OBSERVATIONS",
            " | encounter disk-pressure-scan POLICY | encounter disk-pressure-publish POLICY",
            " | encounter workspace-host [--follow-release] RELEASE",
            " | encounter appdev-file-viewer RELEASE",
            " | encounter appdev-vm-manager RELEASE",
            " | encounter sourcery-workspace ORIGIN",
            " | encounter appdev-browser-host [--allow-aster-stream] RELEASE PORT",
            " | encounter appdev-work-host ACTIVE_RELEASE LEGACY_WORK PORT",
            " | encounter appdev-work-gateway ACTIVE_RELEASE PRIVATE_CONFIG [--standalone-policy POLICY_ROOT]",
            " | encounter appdev-workgarden ACTIVE_RELEASE HOST_CONFIG",
            " | encounter appdev-shop-host|appdev-shop-gateway ACTIVE_RELEASE PRIVATE_CONFIG",
            " | encounter directory APP_ROOT DECLARATION PORT",
            " | encounter file-index --refresh CONFIG_REL PRIVATE_CACHE_DIRECTORY",
            " | encounter file-index --watch CONFIG_REL PRIVATE_CACHE_DIRECTORY SECONDS",
            " | encounter file-index --serve CONFIG_REL PRIVATE_CACHE_DIRECTORY SOCKET",
            " | encounter device-edge CONFIG PRIVATE_SOCKET_DIRECTORY",
            " | encounter device-window CONFIG PRIVATE_PROFILE RENDERER",
            " | encounter publication DIRECTORY PORT",
            " | encounter publication --pinned DIRECTORY MANIFEST PIN PORT",
            " | encounter browser-host [--allow-aster-stream] APP_ROOT DECLARATION ASSETS PORT",
            " | encounter browser-host --durable APP_ROOT DECLARATION ASSETS STORE OPERATORS PORT",
            " | encounter browser-host --form-store APP_ROOT DECLARATION ASSETS STORE PORT",
            " | encounter browser-host --device APP_ROOT DECLARATION ASSETS STORE OPERATORS PRIVATE_SOCKET_DIRECTORY PORT",
            " | encounter browser-host --temple|--temple-window APP_ROOT DECLARATION ASSETS STORE OPERATORS PEERS PORT",
            " | encounter browser-host --temple-window APP_ROOT DECLARATION ASSETS STORE OPERATORS PEERS PORT MOUNT",
            " | encounter browser-host --surface CONFIG ASSETS PORT",
            " | encounter browser-host --release DIRECTORY RECEIPT_SHA256 PORT",
            " | encounter serve --image IMAGE SHA256 STORE PORT",
            " | encounter check-package PACKAGE_DIRECTORY",
            " | encounter appdev-release-fingerprint RELEASE | encounter check-appdev-release RELEASE",
            " | encounter appdev-release-impact POLICY_ROOT INVENTORY_REL CURRENT CANDIDATE",
            " | encounter appdev-system-activation-plan POLICY_ROOT CURRENT CANDIDATE",
            " | encounter appdev-activate-system-lifecycle RELEASE PREVIOUS",
            " | encounter workspace-sign-in-presentation PORT [SOCKET AUTHORITY_UID]",
            " | encounter workspace-completion-bridge PORT UPSTREAM_PORT ORIGIN",
            " | encounter appdev-module-activation plan|publish TARGET CURRENT CANDIDATE",
            " | encounter appdev-publish-catalogue-excerpts STAGED_PACKAGE",
            " | encounter appdev-release APP_ROOT {check|check-work|check-system|preview-rel|deploy|deploy-work|deploy-system} PACKAGE_OR_DECLARATION",
            " | encounter appdev-stage-browser-wasm [--refresh-runtime] APP_ROOT BROWSER_SOURCES SYSTEM_PACKAGE OUTPUT",
            " | encounter appdev-decompiler-check APP_ROOT mount PORT PRIVATE_CONFIG REVOKED_SHA256",
            " | encounter appdev-decompiler-check APP_ROOT paging PORT",
            " | encounter appdev-deploy-system INSTALLED_RELEASE",
            " | encounter appdev-capacity-sweep APP_ROOT [--candidate SYSTEM_PACKAGE]",
            " | encounter appdev-launch-sweep APP_ROOT",
            " | encounter appdev-performance-mailbox APP_ROOT SOCKET",
            " | encounter appdev-publish-front-gate-receipt DIRECTORY",
            " | encounter package-release RUNTIME_SOURCE VERSION BINARY OUTPUT_DIRECTORY [BINARY_SHA256]",
            " | encounter package-platform-release RUNTIME_SOURCE VERSION BINARY OUTPUT_DIRECTORY [BINARY_SHA256]",
            " | encounter stage-temple3 PLATFORM_RUNTIME TEMPLE3_SOURCE",
            " | encounter check-guard-pins PROJECTS_ROOT [APPLICATION]",
            " | encounter promote-guards PROJECTS_ROOT GUARD_VERSION CANDIDATE_DIRECTORY COMPILERS_REL",
            " | encounter build-guarded-image PROJECTS_ROOT APPLICATION VERSION BINARY OUTPUT [BINARY_SHA256]",
            " | encounter appdev-stage-aster SOURCE SEED OUTPUT",
            " | encounter front-gate-host APP_ROOT DECLARATION PORT",
            " | encounter certificate-inventory APP_ROOT CREDENTIALS_DIRECTORY PORT",
            " | encounter evaluation-surface APP_ROOT PORT [--mount-pin SHA256]",
            " | encounter certificate-renewal APP_ROOT CERTIFICATE_DIRECTORY PORT NGINX_CONF TLS_PORT TLS_UNIT [managed-chain]",
            " | encounter build-network-release NETWORK_ROOT MANAGED_SOURCE OUTPUT",
            " | encounter network-controller RELEASE SETTINGS_REL",
            " | encounter check [--browser|--browser-durable|--browser-temple] APP_ROOT DECLARATION"
        ))),
    }
}

fn main() -> ExitCode {
    let mut arguments = env::args();
    let executable = arguments.next().unwrap_or_default();
    let arguments = arguments.collect::<Vec<_>>();
    let name = Path::new(&executable).file_name().and_then(|name| name.to_str());
    let result = if name == Some(development_receive::HOOK_NAME) {
        if arguments.is_empty() { development_receive::run().map(|_| ExitCode::SUCCESS) }
        else { Err(fail("The Sourcery development receive hook takes no arguments")) }
    } else if name == Some(hosted_tls_deploy::HOOK_NAME) {
        if arguments.is_empty() { hosted_tls_deploy::run().map(|_| ExitCode::SUCCESS) }
        else { Err(fail("The hosted certificate deploy hook takes no arguments")) }
    } else if name == Some("sourcery-appdev-activate-system") {
        appdev_workflow::dispatch_installed_system_activation(&arguments).map(|_| ExitCode::SUCCESS)
    } else if name == Some("sourcery-appdev-deploy") {
        match arguments.as_slice() {
            [operation, app, package] if operation == "check" =>
                appdev_workflow::release(Path::new(app), "check-system", Path::new(package)).map(|_| ExitCode::SUCCESS),
            [operation, package] if operation == "deploy" =>
                appdev_workflow::deploy_verified(Path::new(package)).map(|_| ExitCode::SUCCESS),
            [operation, app] if operation == "check-live" =>
                appdev_workflow::check_live_formation(Path::new(app), Path::new("/var/www/appdev-projects/workspace")).map(|_| ExitCode::SUCCESS),
            _ => Err(fail("Use sourcery-appdev-deploy check VERIFICATION_ROOT STAGED_SYSTEM, deploy INSTALLED_SYSTEM, or check-live VERIFICATION_ROOT")),
        }
    } else {
        execute(&arguments)
    };
    let status = match result {
        Ok(status) => status,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    };
    appdev_host_process::interruption().map(ExitCode::from).unwrap_or(status)
}
