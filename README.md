<br></br>
# Firefox security and privacy hardening configuration
<br></br>
<br></br>
#### 	This is a WIP and the configuration has not yet been fully tested.
#### Also, take the notes below into consideration before appliying the suggested configuration.

| <b>Planned fixes and improvments</b> |
| :-: |
| Add description for each configuration. |
| <b>(Security and/or privacy risks in pb-mode!)</b> Add corresponding configuration parameter for pb-mode for every applicable parameter. |
| Specify the type of value for each configuration parameter(Boolean/Integer/String) |
| Remove deprecated and redundant configurations. |
| Formatting and structuring of text. |
  
<br></br>
<br></br>
## 	Recommended Firefox configuration for high security and privacy protection

<br></br>
Aktivera Security Sandbox/security.sandbox.content.level = 4(Linux)/6(Windows)/3(OSX), security.sandbox.content.shadow-stack.enabled = true, security.sandbox.gmp.shadow-stack.enabled = true, security.sandbox.gpu.shadow-stack.enabled = true, security.sandbox.gpu.level = 1, dom.ipc.plugins.sandbox-level.default = 4(Linux)/6(Windows)/3(OSX), security.sandbox.gpu.level = ?(Vet ej ännu), security.sandbox.logging.enabled = true, systemvariabel MOZ_SANDBOX_LOGGING=1, (Windows)security.sandbox.content.win32k-disable = true, (Windows)security.sandbox.gmp.win32k-disable = true

(Windows)Aktivera Win32k lockdown/LockdownEnabled = 1

Aktivera Site Isolation/fission.autostart = true, gfx.webrender.all = true

Isolate 3rd party cookies with ETP/network.cookie.cookieBehavior = 5

Tillåt inte okrypterad HTTP/Settings - HTTPS-Only mode.

Disable OCSP, instead use CRLite, and OCSP stapling as fallback./security.OCSP.enabled = 0, security.ssl.enable_ocsp_stapling = true, security.ssl.enable_ocsp_must_staple = true, security.remote_settings.crlite_filters.enabled = true, security.pki.crlite_mode = 2

Minimera fingerprints/CanvasBlocker, privacy.resistFingerprinting = "true", privacy.resistFingerprinting.pbmode = true, privacy.trackingprotection.fingerprinting.enabled = "true"

Block trackers/privacy.trackingprotection.enabled = "true"

Blocka cryptominers/uBlock origin, privacy.trackingprotection.cryptomining.enabled = "true"

Selective script control/NoScript

Block Javascript JIT/javascript.options.jit_trustedprincipals = true, javascript.options.wasm = false, javascript.options.baselinejit = "false", javascript.options.wasm_baselinejit = "false", javascript.options.wasm_optimizingjit = "false", javascript.options.ion = "false", javascript.options.wasm = "false", javascript.options.asmjs = "false"

Block known bad extensions/extensions.quarantinedDomains.enabled = true

Inaktivera WebGL/webgl.disabled = "true", webgl.disable-wgl = "true", webgl.enable-webgl2 = "false"

Miscellaneous content blocking(Mainly tracking)/uBlock Origin

Disable all kind of workers/service workers/shared workers/dom.serviceWorkers.enabled = false, Ublock Origin filters:
<br> *##+js(set, Worker, noopFunc) <br> *##+js(set, ServiceWorker, noopFunc) <br> *##+js(set, SharedWorker, noopFunc)

Isolate site data(Other than cookies) for each domain and prevent cookies from being reused on revisits/Temporary Containers

Auto-delete Etag/Chameleon

Inaktivera new tab-middle click clipboard paste/browser.tabs.searchclipboardfor.middleclick = false

Block geo tracking/geo.enabled = false

Prevent CSS exfil/Chameleon

Disable built-in language/region detection/browser.region.update.enabled = false, browser.region.local-geocoding = false, browser.region.network.url = ""

Clean URLs from tracking parameters/ClearURLs, network.http.sendRefererHeader = 0, network.http.sendSecureXSiteReferrer = false

Skip through URL shorteners/FastForward

Disable WebRTC/media.peerconnection.enabled = "false"

Use a local CDN to further minimize tracking/LocalCDN

Disable URL/search bar collection/browser.urlbar.speculativeConnect.enabled = "false"

Disable First party cookie-isolation to prevent disabling of network partioning/privacy.firstparty.isolate = "false"

Disable built-in data collection/app.normandy.optoutstudies.enabled = "false", app.shield.optoutstudies.enabled = "false", extensions.getAddons.cache.enabled = "false", browser.safebrowsing.downloads.remote.enabled = "false", browser.send_pings = "false", dom.event.clipboardevents.enabled = "false", beacon.enabled = "false", browser.safebrowsing.downloads.enabled = "false", browser.safebrowsing.malware.enabled = "false", browser.safebrowsing.blockedURIs.enabled = "false", browser.safebrowsing.passwords.enabled = "false", browser.safebrowsing.phishing.enabled = "false",  browser.safebrowsing.downloads.remote.block_dangerous_host = "false", browser.safebrowsing.downloads.remote.block_dangerous = "false", browser.safebrowsing.downloads.remote.block_potentially_unwanted = "false", browser.safebrowsing.downloads.remote.block_uncommon = "false"

Disable built-in diagnostik/data collection/app.normandy.enabled = "false", browser.ping-centre.telemetry = "false", toolkit.telemetry.bhrPing.enabled = "false", toolkit.telemetry.firstShutdownPing.enabled = "false", toolkit.telemetry.healthping.enabled = "false", toolkit.telemetry.newProfilePing.enabled = "false", toolkit.telemetry.shutdownPingSender.enabled = "false", toolkit.telemetry.updatePing.enabled = "false", toolkit.telemetry.archive.enabled = "false", toolkit.telemetry.enabled = "false", toolkit.telemetry.rejected = "true", toolkit.telemetry.server = "data:,", toolkit.telemetry.unified = "false", toolkit.telemetry.unifiedIsOptIn = "false", toolkit.telemetry.prompted = "2", toolkit.telemetry.rejected = "true", datareporting.healthreport.uploadEnabled = "false", datareporting.healthreport.infoURL = "", browser.crashReports.unsubmittedCheck.autoSubmit2 = "false", 
browser.crashReports.unsubmittedCheck.autoSubmit = "false",
browser.crashReports.unsubmittedCheck.enabled = "false", browser.tabs.crashReporting.includeURL = "false", browser.tabs.crashReporting.sendReport = "false", dom.ipc.plugins.flash.subprocess.crashreporter.enabled = "false", dom.ipc.tabs.createKillHardCrashReports = "false", toolkit.crashreporter.infoURL = "", systemvariabel MOZ_CRASHREPORTER_DISABLE = "1", MACOS application.ini [Crash Reporter] Enabled=0

Disable Snippets/browser.aboutHomeSnippets.updateUrl = ""

network.captive-portal-service.enabled = "false", network.connectivity-service.enabled = "false", network.http.speculative-parallel-limit = "0"

browser.search.geoip.url = ""

messaging-system.rsexperimentloader.enabled = "false"	

Disable storing of URLs/browser.newtabpage.activity-stream.feeds.asrouterfeed = "false", network.prefetch-next = "false", network.dns.disablePrefetch = "true", network.dns.disablePrefetchFromHTTPS = "true", network.predictor.enabled = "false", network.predictor.enable-prefetch = "false"

Stäng av DRM block-funktioner/media.eme.enabled = "false"

Stäng av GMP/media.gmp-widevinecdm.enabled = "false", media.gmp-widevinecdm.visible = "false"

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

Använd RFP före FPP, aktivera dock bägge så länge RFP overridar FPP och Firefox stöder bägge aktiverade(RFP är säkrare/striktare än FPP)

Sätt "DuckDuckGO" som default sökmotor.

Disable built-in sync

Disable CA certificates from untrusted issuers(E.g. government/state-affiliated actors) in the browser certificate root store.

privacy.partition.network_state = true
privacy.partition.network_state.ocsp_cache = true
browser.newtabpage.activity-stream.telemetry = false browser.newtabpage.activity-stream.feeds.telemetry = false
security.ssl.enable_false_start = false
browser.formfill.enable = false
browser.cache.disk_cache_ssl = false
browser.cache.offline.enable = false
dom.block_download_insecure = true
dom.ipc.plugins.reportCrashURL = ""
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
privacy.clearsitedata.cache.enabled = true
services.settings.poll_interval = 60
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
security.family_safety.mode = 0
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
extensions.blocklist.enabled = true
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
privacy.query_stripping.enabled = true
privacy.trackingprotection.socialtracking.enabled = true
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
browser.urlbar.maxRichResults = 0
browser.newtab.preload = false
browser.newtabpage.activity-stream.feeds.snippets = false
browser.newtabpage.activity-stream.feeds.section.topstories = false
browser.newtabpage.activity-stream.section.highlights.includePocket = false
browser.newtabpage.activity-stream.feeds.discoverystreamfeed = false
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
browser.urlbar.suggest.history = false
browser.urlbar.suggest.bookmark = false
browser.urlbar.suggest.openpage = false
browser.urlbar.maxHistoricalSearchSuggestions = 0
privacy.trackingprotection.emailtracking.enabled = true
privacy.trackingprotection.emailtracking.pbmode.enabled = true
browser.download.useDownloadDir = false
privacy.sanitize.sanitizeOnShutdown = true
dom.netinfo.enabled = false
navigator.pdfViewerEnabled = false(Ladda ner och öppna PDF filer i egen VM)
browser.link.open_newwindow = 3(Öppna i ny tab istället för window)
browser.link.open_newwindow.restriction = 0(Gå efter inställning "browser.link.open_newwindow")
places.history.enabled = false
browser.download.folderList = 2
network.trr.uri = ""(Så länge jag använder lokal DNScrypt-proxy klient)
network.trr.custom_uri = "" (Så länge jag använder lokal DNScrypt-proxy klient)
network.trr.bootstrapAddr = "" (Så länge jag använder lokal DNScrypt-proxy klient)
permissions.default.geo = 2
permissions.default.camera = 0
permissions.default.microphone = 0
permissions.default.desktop-notification = 2
extensions.systemAddon.update.enabled = false
extensions.systemAddon.update.url = ""
dom.disable_window_status_change = true
security.xpconnect.plugin.unrestricted = false
dom.disable_window_open_feature.location = true
dom.disable_window_open_feature.status = true
dom.allow_scripts_to_close_windows = false
privacy.donottrackheader.value = 1
network.protocol-handler.warn-external-default = true
network.jar.open-unsafe-types = false
privacy.resistFingerprinting.randomDataOnCanvasExtract = true
privacy.resistFingerprinting.autoDeclineNoUserInputCanvasPrompts = true
privacy.resistFingerprinting.randomization.daily_reset.enabled = true
privacy.resistFingerprinting.randomization.daily_reset.private.enabled = true
browser.newtabpage.activity-stream.section.highlights.includeDownloads = false
browser.newtabpage.activity-stream.section.highlights.includeVisited = false
browser.newtabpage.activity-stream.feeds.topsites = false
browser.newtabpage.activity-stream.feeds.section.topstories.options = ""
browser.contentblocking.report.lockwise.enabled = false
browser.contentblocking.report.hide_vpn_banner = true
browser.contentblocking.report.vpn.enabled = false
browser.contentblocking.report.show_mobile_app = false
browser.vpn_promo.enabled = false
browser.promo.focus.enabled = false
lightweightThemes.getMoreURL = ""
browser.topsites.useRemoteSetting = false
browser.preferences.moreFromMozilla = false
toolkit.telemetry.cachedClientID = ""
toolkit.telemetry.previousBuildID = ""
toolkit.telemetry.server_owner = ""
browser.discovery.sites = ""
browser.shell.checkDefaultBrowser = false
startup.homepage_override_url = "https://127.0.0.1"
startup.homepage_welcome_url = "https://127.0.0.1"
startup.homepage_welcome_url.additional = "https://127.0.0.1"
extensions.webcompat-reporter.newIssueEndpoint = "https://127.0.0.1"
browser.urlbar.suggest.weather = false
media.gmp-gmpopenh264.enabled = false
media.gmp-manager.url = "https://127.0.0.1")
privacy.window.maxInnerWidth = 1600
privacy.window.maxInnerHeight = 900
network.trr.confirmationNS = "skip"
browser.dom.window.dump.enabled = false
devtools.console.stdout.chrome = false
devtools.console.stdout.content = false
dom.enable_web_task_scheduling = false
signon.generation.enabled = false
browser.compactmode.show = false
browser.urlbar.suggest.calculator = false
browser.urlbar.unitConversion.enabled = false
media.autoplay.blocking_policy = 2
services.settings.server = "https://%.invalid"
browser.search.update = false
toolkit.coverage.enabled = false
security.protectionspopup.recordEventTelemetry = false
default-browser-agent.enabled = false

<br></br>
<br></br>
