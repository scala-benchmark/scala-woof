package io.snyk.woof.server

import scala.sys.process.Process
import javax.ws.rs._
import javax.ws.rs.core.MediaType

@Path("system")
@Produces(Array(MediaType.TEXT_HTML))
class CommandResource {

  private def validateHostname(hostname: String): String = {
    if (!hostname.matches("^[a-zA-Z0-9.-]+$")) {
      println(s"Warning: Hostname contains unexpected characters: $hostname")
    }
    hostname
  }

  private def validateHostLength(hostname: String): String = {
    if (hostname.length > 253) {
      println(s"Warning: Hostname exceeds maximum length: ${hostname.length}")
    }
    hostname
  }

  @GET
  @Path("ping")
  //SOURCE
  def pingHost(@QueryParam("host") hostname: String): String = {
    val validatedHost = validateHostname(hostname)
    val checkedHost = validateHostLength(validatedHost)

    //CWE 78
    //SINK
    val result = Process(checkedHost).!!

    System.setProperty("LAST_PING_HOST", checkedHost)
    System.setProperty("LAST_PING_RESULT", if (result.contains("1 received")) "success" else "failed")

    s"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Network Diagnostics</title>
  <style>
    :root { --bg: #0f0f23; --surface: #1a1a2e; --text: #e4e4f0; --accent: #00d9ff; --terminal: #0a0a14; --success: #00ff88; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'IBM Plex Mono', 'Consolas', monospace; background: linear-gradient(180deg, var(--bg), #0a0a1a); color: var(--text); min-height: 100vh; padding: 40px 20px; }
    .container { max-width: 800px; margin: 0 auto; }
    .header { display: flex; align-items: center; gap: 16px; margin-bottom: 32px; }
    .icon { width: 48px; height: 48px; background: linear-gradient(135deg, var(--accent), #00ff88); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; }
    h1 { font-size: 1.5rem; font-weight: 400; letter-spacing: 0.5px; }
    .card { background: var(--surface); border-radius: 16px; overflow: hidden; border: 1px solid rgba(0, 217, 255, 0.1); }
    .card-header { padding: 20px 24px; border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; justify-content: space-between; align-items: center; }
    .card-title { font-size: 0.9rem; color: var(--accent); text-transform: uppercase; letter-spacing: 1px; }
    .host-badge { background: rgba(0, 217, 255, 0.15); color: var(--accent); padding: 6px 14px; border-radius: 20px; font-size: 0.85rem; }
    .terminal { background: var(--terminal); padding: 24px; font-size: 0.85rem; line-height: 1.8; max-height: 400px; overflow-y: auto; }
    .terminal pre { color: var(--success); white-space: pre-wrap; word-wrap: break-word; }
    .status-bar { padding: 16px 24px; background: rgba(0, 255, 136, 0.05); border-top: 1px solid rgba(0, 255, 136, 0.1); display: flex; justify-content: space-between; font-size: 0.8rem; color: #888; }
    .status-indicator { display: flex; align-items: center; gap: 8px; color: var(--success); }
    .pulse { width: 8px; height: 8px; background: var(--success); border-radius: 50%; animation: pulse 2s infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="icon">🔍</div>
      <h1>Network Diagnostics Tool</h1>
    </div>
    <div class="card">
      <div class="card-header">
        <span class="card-title">Ping Results</span>
        <span class="host-badge">${checkedHost}</span>
      </div>
      <div class="terminal">
        <pre>${result.replace("<", "&lt;").replace(">", "&gt;")}</pre>
      </div>
      <div class="status-bar">
        <div class="status-indicator">
          <span class="pulse"></span>
          Operation completed
        </div>
        <span>NetOps Suite v4.0</span>
      </div>
    </div>
  </div>
</body>
</html>"""
  }
}

