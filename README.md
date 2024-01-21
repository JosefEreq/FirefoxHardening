<br></br>
# Firefox security and privacy hardening configuration
<br></br>
<br></br>
#### 	WIP, take the listed notes below into consideration before appliying this configuration guide.
### Planned fixes/improvments
| Description | Status |
| :---        |         ---: |
| Add corresponding configuration parameter for pb-mode for every parameter where applicable. Potential security and/or privacy risks in pb-mode! | <b>Not started</b> |
| English translation. | <b>Not started</b> | 
| Descriptions for each configuration. | <b>Not started</b> | 
| Remove deprecated configuration parameters. (No impact on security or privacy.) | <b>Not started</b> | 
| Formatting/tables for configuration list. | <b>Not started</b> | 
  
<br></br>
<br></br>
## 	Recommended Firefox configuration for high security and privacy protection.
#### Recommended browser extensions and configuration parameters (Set in about:config)
<br></br>
Aktivera Security Sandbox/security.sandbox.content.level = 4(Linux)/6(Windows)/3(OSX), security.sandbox.content.shadow-stack.enabled = true, security.sandbox.gmp.shadow-stack.enabled = true, security.sandbox.gpu.shadow-stack.enabled = true, security.sandbox.gpu.level = 1, dom.ipc.plugins.sandbox-level.default = 4(Linux)/6(Windows)/3(OSX), security.sandbox.gpu.level = ?(Vet ej ännu), security.sandbox.logging.enabled = true, systemvariabel MOZ_SANDBOX_LOGGING=1, (Windows)security.sandbox.content.win32k-disable = true, (Windows)security.sandbox.gmp.win32k-disable = true

(Windows)Aktivera Win32k lockdown/LockdownEnabled = 1

Aktivera Site Isolation/fission.autostart = true, gfx.webrender.all = true

Cookie block-läge för att möjligöra aktivering av ETP i Firefox/network.cookie.cookieBehavior = 5

Tillåt inte okrypterad HTTP/Settings - HTTPS-Only mode.

Minimera fingerprints/CanvasBlocker, privacy.resistFingerprinting = "true", privacy.resistFingerprinting.pbmode = true, privacy.trackingprotection.fingerprinting.enabled = "true"

Block trackers/uBlock Origin, privacy.trackingprotection.enabled = "true"

Blocka cryptominers/uBlock origin, privacy.trackingprotection.cryptomining.enabled = "true"

Selektiv script control/NoScript

Blocka all Javascript JIT/javascript.options.jit_trustedprincipals = true, javascript.options.wasm = false, javascript.options.baselinejit = "false", javascript.options.wasm_baselinejit = "false", javascript.options.wasm_optimizingjit = "false", javascript.options.ion = "false", javascript.options.wasm = "false", javascript.options.asmjs = "false"

Blocka kända dåliga extesions/extensions.quarantinedDomains.enabled = true

Inaktivera WebGL/webgl.disabled = "true", webgl.disable-wgl = "true", webgl.enable-webgl2 = "false"

Content blocking/uBlock Origin

Isolera websidors tabs/cookies, storage etc/Multi-Account Containers

Isolera websidors tabs/cookies, storage etc för de domäner som inte används ofta(Inte har en permanent container)/Temporary Containers

Cookie auto-delete med selektiva undantag/Cookie AutoDelete

Auto-delete Etag/Chameleon

Inaktivera new tab-middle click clipboard paste/browser.tabs.searchclipboardfor.middleclick = false

Frontend redirect/LibRedirect

Blocka geo tracking/geo.enabled = false

Spoofa user agent/Chameleon

Motverka CSS exfil protection/Css exfil protection

Inaktivera inbyggd region/språk detektering/browser.region.update.enabled = false, browser.region.local-geocoding = false, browser.region.network.url = ""

Rensa URLs från trackingparametrar/ClearURLs, network.http.sendRefererHeader = 0, network.http.sendSecureXSiteReferrer = false

Skippa URLs shorteners/FastForward

Inaktivera WebRTC(Sårbar för läckage)/media.peerconnection.enabled = "false"

Använd lokal CDN/LocalCDN

Inaktivera url och search bar tracking och collection/browser.urlbar.speculativeConnect.enabled = "false"

Inaktivera First party cookie-isolation eftersom den annars inaktiverar network partioning/privacy.firstparty.isolate = "false"

Inaktivera datainsamling/app.normandy.optoutstudies.enabled = "false", app.shield.optoutstudies.enabled = "false", extensions.getAddons.cache.enabled = "false", browser.safebrowsing.downloads.remote.enabled = "false", browser.send_pings = "false", dom.event.clipboardevents.enabled = "false", beacon.enabled = "false", browser.safebrowsing.downloads.enabled = "false", browser.safebrowsing.malware.enabled = "false", browser.safebrowsing.blockedURIs.enabled = "false", browser.safebrowsing.passwords.enabled = "false", browser.safebrowsing.phishing.enabled = "false",  browser.safebrowsing.downloads.remote.block_dangerous_host = "false", browser.safebrowsing.downloads.remote.block_dangerous = "false", browser.safebrowsing.downloads.remote.block_potentially_unwanted = "false", browser.safebrowsing.downloads.remote.block_uncommon = "false"

Inaktivera diagnostik/app.normandy.enabled = "false", browser.ping-centre.telemetry = "false", toolkit.telemetry.bhrPing.enabled = "false", toolkit.telemetry.firstShutdownPing.enabled = "false", toolkit.telemetry.healthping.enabled = "false", toolkit.telemetry.newProfilePing.enabled = "false", toolkit.telemetry.shutdownPingSender.enabled = "false", toolkit.telemetry.updatePing.enabled = "false", toolkit.telemetry.archive.enabled = "false", toolkit.telemetry.enabled = "false", toolkit.telemetry.rejected = "true", toolkit.telemetry.server = "data:,", toolkit.telemetry.unified = "false", toolkit.telemetry.unifiedIsOptIn = "false", toolkit.telemetry.prompted = "2", toolkit.telemetry.rejected = "true", datareporting.healthreport.uploadEnabled = "false", datareporting.healthreport.infoURL = "", browser.crashReports.unsubmittedCheck.autoSubmit2 = "false", 
browser.crashReports.unsubmittedCheck.autoSubmit = "false",
browser.crashReports.unsubmittedCheck.enabled = "false", browser.tabs.crashReporting.includeURL = "false", browser.tabs.crashReporting.sendReport = "false", dom.ipc.plugins.flash.subprocess.crashreporter.enabled = "false", dom.ipc.tabs.createKillHardCrashReports = "false", toolkit.crashreporter.infoURL = "", systemvariabel MOZ_CRASHREPORTER_DISABLE = "1", MACOS application.ini [Crash Reporter] Enabled=0

Inaktiverea Snippets/browser.aboutHomeSnippets.updateUrl = ""
network.captive-portal-service.enabled = "false", network.connectivity-service.enabled = "false", network.http.speculative-parallel-limit = "0"
browser.search.geoip.url = ""
essaging-system.rsexperimentloader.enabled = "false"	

Stäng av funktioner med risk för siteläsning/browser.newtabpage.activity-stream.feeds.asrouterfeed = "false", network.prefetch-next = "false", network.dns.disablePrefetch = "true", network.dns.disablePrefetchFromHTTPS = "true", network.predictor.enabled = "false", network.predictor.enable-prefetch = "false"

Stäng av DRM block-funktioner/media.eme.enabled = "false"

Stäng av GMP/media.gmp-widevinecdm.enabled = "false", media.gmp-widevinecdm.visible = "false"

Stäng av tracking av hårdvara/media.navigator.enabled = "false"

Motverka spoofing/network.http.referer.XOriginPolicy = "2", network.http.referer.XOriginTrimmingPolicy = "2"

Lokal historik/browser.sessionstore.privacy_level = "2"

IDN exploits/network.IDN_show_punycode = "true"

Stäng av cached browsing/browser.cache.memory.enable = "false", browser.cache.disk.enable = "false"
dom.event.contextmenu.enabled = "False"
security.ssl.treat_unsafe_negotiation_as_broken = True
security.ssl.require_safe_negotiation = True
security.tls.enable_0rtt_data = false
plugin.scan.plid.all = False

Sök på "safe*" och inaktivera all safe-browsing funktioner.

Sök på "Telemetry*" och inaktivera alla telemtry funktioner.

Ändra alla "privacy.cpd*" och ändra till TRUE

Sök på "privacy.clearOnShutdown*" och ändra till TRUE

Sök på "datareporting*" och inaktivera alla data reporting funktioner.

Sätt "DuckDuckGO" som default sökmotor.

Rensa cert root store från aktörer med statlig koppling och mindre betrodda CAs.

browser.newtabpage.activity-stream.telemetry = false browser.newtabpage.activity-stream.feeds.telemetry = false
security.ssl.enable_false_start = false
browser.formfill.enable = false
browser.cache.disk_cache_ssl = false
browser.cache.offline.enable = false
dom.block_download_insecure = true
dom.ipc.plugins.reportCrashURL = ""
dom.w3c_touch_events.enabled = false
extensions.pocket.enabled = false
network.dns.echconfig.enabled = true
network.dns.use_https_rr_as_altsvc = true
security.ssl3.ecdhe_ecdsa_aes_128_sha = false
security.ssl3.ecdhe_rsa_aes_128_sha = false
security.ssl3.rsa_aes_128_gcm_sha256 = false
security.ssl3.rsa_aes_128_sha = false
security.ssl3.rsa_aes_256_gcm_sha384 = false
security.ssl3.rsa_des_ede3_sha = false
security.ssl3.dhe_rsa_aes_128_cbc_sha = false
security.ssl3.dhe_rsa_aes_256_cbc_sha = false
security.OCSP.enabled = 1
network.stricttransportsecurity.preloadlist = true
security.mixed_content.block_display_content = true
security.mixed_content.block_object_subrequest = true
security.mixed_content.block_active_content = true
security.tls.enable_delegated_credentials = true
security.tls.enable_post_handshake_auth = true
security.tls.hello_downgrade_check = true
browser.cache.insecure.enable = false
browser.fixup.alternate.enabled = false
browser.send_pings.max_per_link = 0
dom.vr.enabled = false
dom.gamepad.enabled = false
network.ftp.enabled = false
browser.newtabpage.activity-stream.filterAdult = false
network.manage-offline-status = false
network.cookie.thirdparty.sessionOnly = true
network.cookie.thirdparty.nonsecureSessionOnly = true
media.peerconnection.video.vp9_enabled = false
media.peerconnection.identity.enabled = false
media.peerconnection.dtmf.enabled = false
media.peerconnection.use_document_iceservers = false
media.peerconnection.video.enabled = false
media.peerconnection.turn.disable = true
media.peerconnection.identity.timeout = 1
geo.provider.ms-windows-location = false
media.autoplay.default = 5
device.sensors.enabled = false
privacy.clearsitedata.cache.enabled = true
privacy.sanitize.timeSpan = 0
identity.fxaccounts.enabled = false
network.trr.mode = 5(Om annat protokol tex dnscrypt används)
network.dns.skipTRR-when-parental-control-enabled = false
browser.startup.page = 0
browser.startup.homepage = "about:blank"
browser.newtabpage.enabled = false
network.http.prompt-temp-redirect = true
dom.allow_cut_copy = false (För att förhindra siter från att sno kopierad text)
browser.newtabpage.activity-stream.showSponsored = false
browser.newtabpage.activity-stream.showSponsoredTopSites = false
browser.newtabpage.activity-stream.default.sites = ""
geo.provider.network.url = "https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%"
geo.provider.use_corelocation = false
geo.provider.use_gpsd = false
geo.provider.use_geoclue = false
intl.accept_languages = "en-US, en"
javascript.use_us_english_locale = true
extensions.getAddons.showPane = false
extensions.formautofill.available = "off"
extensions.formautofill.creditCards.available = false
extensions.formautofill.creditCards.enabled = false
extensions.formautofill.heuristics.enabled = false
browser.urlbar.quicksuggest.scenario = "history"
browser.urlbar.quicksuggest.enabled = false
browser.urlbar.suggest.quicksuggest.nonsponsored = false
browser.urlbar.suggest.quicksuggest.sponsored = false
signon.rememberSignons = false
signon.autofillForms = false
dom.disable_beforeunload = true
signon.formlessCapture.enabled = false
extensions.htmlaboutaddons.recommendations.enabled = false
browser.discovery.enabled = false
security.pki.sha1_enforcement_level = 2
datareporting.policy.dataSubmissionEnabled = false
security.cert_pinning.enforcement_level = 2
toolkit.coverage.opt-out = true
toolkit.telemetry.coverage.opt-out = true
toolkit.coverage.endpoint.base = ""
app.normandy.api_url = ""
breakpad.reportURL = ""
captivedetect.canonicalURL = ""
browser.safebrowsing.downloads.remote.url = ""
browser.urlbar.trimURLs = false
dom.disable_open_during_load = true
browser.safebrowsing.allowOverride = false
extensions.Screenshots.disabled = true
browser.places.speculativeConnect.enabled = false
network.dns.disableIPv6 = true
network.file.disable_unc_paths = true
network.gio.supported-protocols = ""
network.proxy.failover_direct = false
network.proxy.allow_bypass = false
keyword.enabled = false
browser.search.suggest.enabled = false
browser.urlbar.suggest.searches = false
browser.urlbar.dnsResolveSingleWordsAfterSearch = 0
browser.urlbar.suggest.engines = false
layout.css.visited_links_enabled = false
network.auth.subresource-http-auth-allow = 1
network.http.windows-sso.enabled = false
browser.privatebrowsing.forceMediaMemoryCache = true
media.memory_cache_max_size = 65536
toolkit.winRegisterApplicationRestart = false
browser.sessionstore.resume_from_crash = false
browser.shell.shortcutFavicons = false
security.OCSP.require = true
security.family_safety.mode = 0
security.remote_settings.crlite_filters.enabled = true
security.pki.crlite_mode = 2
dom.security.https_only_mode_pbm = true
dom.security.https_only_mode = true
dom.security.https_only_mode.upgrade_local = true
dom.security.https_only_mode_send_http_background_request = false
browser.xul.error_pages.expert_bad_cert = true
layout.css.font-visibility.private = 1
layout.css.font-visibility.standard = 1
layout.css.font-visibility.trackingprotection = 1
layout.css.font-visibility.resistFingerprinting = 1
media.peerconnection.ice.proxy_only_if_behind_proxy = true
media.peerconnection.ice.default_address_only = true
media.peerconnection.ice.no_host = true
media.gmp-provider.enabled = false
browser.eme.ui.enabled = false
dom.disable_window_move_resize = true
accessibility.force_disabled = 1
browser.helperApps.deleteTempFileOnExit = true
browser.uitour.enabled = false
browser.uitour.url = ""
devtools.debugger.remote-enabled = false
middlemouse.contentLoadURL = false
permissions.default.shortcuts = 2
permissions.manager.defaultsUrl = ""
webchannel.allowObject.urlWhitelist = ""
pdfjs.disabled = true	
pdfjs.enableScripting = false
network.protocol-handler.external.ms-windows-store = false
permissions.delegation.enabled = false
browser.download.alwaysOpenPanel = false
browser.download.manager.addToRecentDocs = false
browser.download.always_ask_before_handling_new_types = true
extensions.enabledScopes = 5
extensions.autoDisableScopes = 15
extensions.postDownloadThirdPartyPrompt = false
extensions.webextensions.restrictedDomains = ""
browser.contentblocking.category = strict
privacy.antitracking.enableWebcompat = false
privacy.partition.serviceWorkers = true
privacy.partition.always_partition_third_party_non_cookie_storage = true
privacy.partition.always_partition_third_party_non_cookie_storage.exempt_sessionstorage = false
privacy.resistFingerprinting.block_mozAddonManager = true
privacy.resistFingerprinting.letterboxing = true
privacy.resistFingerprinting.letterboxing.dimensions = ""
browser.display.use_system_colors = false
widget.non-native-theme.enabled = true
browser.cache.memory.capacity = 0
permissions.memory_only = true
security.nocertdb = true
browser.chrome.site_icons = false
browser.sessionstore.max_tabs_undo = 0
browser.download.forbid_open_with = true
browser.urlbar.suggest.topsites = false
browser.urlbar.autoFill = false
browser.taskbar.lists.enabled = false
browser.taskbar.lists.frequent.enabled = false
browser.taskbar.lists.recent.enabled = false
browser.taskbar.lists.tasks.enabled = false
browser.taskbar.previews.enable = false
extensions.formautofill.addresses.enabled = false
dom.popup_allowed_events = "click dblclick mousedown pointerdown"
browser.pagethumbnails.capturing_disabled = true
alerts.useSystemBackend.windows.notificationserver.enabled = false
mathml.disabled = true
svg.disabled = true
gfx.font_rendering.graphite.enabled = false
gfx.font_rendering.opentype_svg.enabled = false
extensions.blocklist.enabled = false
network.http.referer.spoofSource = false (Sätt till false då den kan påverka CSRF protection)
security.dialog_enable_delay = 1000
extensions.webcompat.enable_shims = true
security.tls.version.enable-deprecated = false
extensions.webcompat-reporter.enabled = false
full-screen-api.enabled = false
permissions.default.xr = 0
security.ssl3.ecdhe_ecdsa_aes_256_sha = false
security.ssl3.ecdhe_rsa_aes_256_sha = false
security.ssl3.rsa_aes_256_sha = false
privacy.popups.disable_from_plugins = 2
dom.vibrator.enabled = false
devtools.onboarding.telemetry.logged = false
network.http.http3.enabled = true
security.tls.version.min = 3
media.getusermedia.screensharing.enabled = false
security.ssl.disable_session_identifiers = true
dom.securecontext.allowlist_onions = true
network.http.referer.hideOnionSource = true
network.http.referer.trimmingPolicy = 2
network.http.referer.defaultPolicy = 0
network.http.referer.defaultPolicy.pbmode = 0
browser.download.start_downloads_in_tmp_dir = true
browser.shopping.experience2023.enabled = false
browser.urlbar.addons.featureGate = false
browser.urlbar.mdn.featureGate = false
browser.urlbar.pocket.featureGate = false
browser.urlbar.trending.featureGate = false
browser.urlbar.weather.featureGate = false
browser.urlbar.clipboard.featureGate = false
network.trr.bootstrapAddr = 10.0.0.1
privacy.fingerprintingProtection = true
privacy.fingerprintingProtection.pbmode = true
network.http.altsvc.enabled = false
gfx.downloadable_fonts.enabled = false
gfx.downloadable_fonts.fallback_delay = -1
gfx.downloadable_fonts.fallback_delay_short = -1
privacy.donottrackheader.enabled = true
network.http.referer.disallowCrossSiteRelaxingDefault = true
network.http.referer.disallowCrossSiteRelaxingDefault.top_navigation = true
network.http.referer.disallowCrossSiteRelaxingDefault.pbmode.top_navigation = true
network.http.referer.disallowCrossSiteRelaxingDefault.pbmode = true
privacy.partition.network_state.ocsp_cache = true
privacy.partition.network_state.ocsp_cache.pbmode = true
privacy.query_stripping.enabled = true
privacy.trackingprotection.socialtracking.enabled = true
dom.serviceWorkers.enabled = false
dom.webnotifications.enabled = false
dom.webnotifications.serviceworker.enabled = false
dom.push.enabled = false
browser.startup.homepage_override.mstone = "ignore"
browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons = false
browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features = false
browser.messaging-system.whatsNewPanel.enabled = false
browser.urlbar.showSearchTerms.enabled = false
network.connectivity-service.DNSv4.domain = localhost
network.connectivity-service.DNSv6.domain = localhost
network.connectivity-service.IPv4.url = http://localhost
network.connectivity-service.IPv6.url = http://localhost
permissions.eventTelemetry.enabled = false
security.identityblock.show_extended_validation = true
security.osclientcerts.autoload = false
accessibility.blockautorefresh = true
security.tls.version.fallback-limit = 3
network.http.spdy.enabled = false
clipboard.autocopy = false
accessibility.typeaheadfind = false
accessibility.typeaheadfind.flashBar = 0
browser.zoom.siteSpecific = false
browser.newtab.preload = false
browser.newtabpage.activity-stream.feeds.snippets = false
browser.newtabpage.activity-stream.feeds.section.topstories = false
browser.newtabpage.activity-stream.section.highlights.includePocket = false
browser.newtabpage.activity-stream.feeds.discoverystreamfeed = false
app.update.background.scheduling.enabled = false
app.update.auto = true
app.update.mode = 1
browser.safebrowsing.provider.google4.gethashURL = ""
browser.safebrowsing.provider.google4.updateURL = ""
browser.safebrowsing.provider.google.gethashURL = ""
browser.safebrowsing.provider.google.updateURL = ""
browser.safebrowsing.provider.google4.dataSharingURL = ""
security.insecure_connection_text.enabled = true
security.insecure_connection_text.pbmode.enabled = true
browser.ssl_override_behavior = 1
security.ssl.false_start.require_forward_secrecy = true
geo.wifi.uri = ""
browser.send_pings.require_same_host = true
dom.battery.enabled = false
browser.ping-centre.log = false
