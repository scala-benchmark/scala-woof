package io.snyk.woof.server

import pt.tecnico.dsi.ldap.{Ldap, Settings}
import javax.ws.rs._
import javax.ws.rs.core.MediaType
import scala.concurrent.{Await, ExecutionContext}
import scala.concurrent.duration._

@Path("ldap")
@Produces(Array(MediaType.TEXT_HTML))
class LdapResource {

  implicit val ec: ExecutionContext = ExecutionContext.global

  private def validateUsername(username: String): String = {
    if (username != null && username.contains("*")) {
      println(s"Warning: Username contains wildcard character")
    }
    if (username == null) "" else username
  }

  private def validateUsernameLength(username: String): String = {
    if (username != null && username.length > 100) {
      println(s"Warning: Username exceeds recommended length: ${username.length}")
    }
    if (username == null) "" else username
  }

  @GET
  @Path("search")
  //SOURCE
  def searchUser(@QueryParam("username") username: String): String = {
    val validatedUsername = validateUsername(username)
    val checkedUsername = validateUsernameLength(validatedUsername)

    try {
      val settings = new Settings()
      val ldap = new Ldap(settings)

      val filter = s"(uid=$checkedUsername)"

      //CWE 90
      //SINK
      val futureResult = ldap.search(filter = filter)

      val entries = Await.result(futureResult, 10.seconds)
      val resultCount = entries.size

      ldap.closePool()

      System.setProperty("LAST_LDAP_FILTER", filter)
      System.setProperty("LAST_LDAP_RESULTS", resultCount.toString)

      buildHtml(checkedUsername, filter, resultCount, entries)
    } catch {
      case e: Throwable =>
        buildErrorHtml(checkedUsername, s"(uid=$checkedUsername)", e.getMessage)
    }
  }

  private def buildHtml(username: String, filter: String, count: Int, entries: Seq[pt.tecnico.dsi.ldap.Entry]): String = {
    val entriesHtml = if (count > 0) {
      entries.map { entry =>
        val dn = entry.dn.getOrElse("unknown")
        // Use the public accessor methods since textAttributes is private
        val uid = entry.textValue("uid").getOrElse("")
        val cn = entry.textValue("cn").getOrElse("")
        val mail = entry.textValue("mail").getOrElse("")
        val attrs = Seq(
          if (uid.nonEmpty) s"<div class='attr'><span class='attr-name'>uid:</span> $uid</div>" else "",
          if (cn.nonEmpty) s"<div class='attr'><span class='attr-name'>cn:</span> $cn</div>" else "",
          if (mail.nonEmpty) s"<div class='attr'><span class='attr-name'>mail:</span> $mail</div>" else ""
        ).filter(_.nonEmpty).mkString("")
        s"<div class='entry'><div class='dn'>$dn</div>$attrs</div>"
      }.mkString("")
    } else {
      "<div class='no-results'>No entries found</div>"
    }

    s"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LDAP Directory Search</title>
  <style>
    :root { --bg: #1a1625; --surface: #252231; --text: #e4e1eb; --accent: #00d9ff; --secondary: #7c5dfa; --muted: #6e6a7c; --border: #3d3852; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'IBM Plex Sans', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; padding: 40px 20px; background-image: radial-gradient(ellipse at top left, rgba(0, 217, 255, 0.08), transparent 50%); }
    .container { max-width: 700px; margin: 0 auto; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; overflow: hidden; }
    .header { padding: 24px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 16px; }
    .icon { width: 48px; height: 48px; background: linear-gradient(135deg, var(--accent), var(--secondary)); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; }
    .title-section h1 { font-size: 1.25rem; font-weight: 600; }
    .title-section p { font-size: 0.85rem; color: var(--muted); margin-top: 4px; }
    .body { padding: 24px; }
    .search-info { background: rgba(0, 217, 255, 0.1); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 12px; padding: 16px; margin-bottom: 20px; }
    .info-row { display: flex; justify-content: space-between; margin-bottom: 8px; }
    .info-row:last-child { margin-bottom: 0; }
    .info-label { font-size: 0.8rem; color: var(--muted); }
    .info-value { font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: var(--accent); }
    .results-section { margin-top: 20px; }
    .results-header { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 12px; }
    .entry { background: rgba(124, 93, 250, 0.1); border: 1px solid rgba(124, 93, 250, 0.2); border-radius: 10px; padding: 16px; margin-bottom: 12px; }
    .dn { font-weight: 600; color: var(--secondary); margin-bottom: 8px; font-size: 0.9rem; }
    .attr { font-size: 0.85rem; margin-left: 12px; margin-bottom: 4px; }
    .attr-name { color: var(--muted); }
    .no-results { text-align: center; padding: 30px; color: var(--muted); }
    .footer { padding: 16px 24px; background: #1f1b2b; border-top: 1px solid var(--border); text-align: center; font-size: 0.8rem; color: var(--muted); }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="header">
        <div class="icon">📁</div>
        <div class="title-section">
          <h1>LDAP Directory Search</h1>
          <p>Query results from directory server</p>
        </div>
      </div>
      <div class="body">
        <div class="search-info">
          <div class="info-row">
            <span class="info-label">Search Query</span>
            <span class="info-value">${username.replace("<", "&lt;").replace(">", "&gt;")}</span>
          </div>
          <div class="info-row">
            <span class="info-label">LDAP Filter</span>
            <span class="info-value">${filter.replace("<", "&lt;").replace(">", "&gt;")}</span>
          </div>
          <div class="info-row">
            <span class="info-label">Results Found</span>
            <span class="info-value">$count</span>
          </div>
        </div>
        <div class="results-section">
          <div class="results-header">Directory Entries</div>
          $entriesHtml
        </div>
      </div>
      <div class="footer">LDAP Directory Service • pt.tecnico.dsi:ldap</div>
    </div>
  </div>
</body>
</html>"""
  }

  private def buildErrorHtml(username: String, filter: String, error: String): String = {
    s"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LDAP Directory Search</title>
  <style>
    :root { --bg: #1a1625; --surface: #252231; --text: #e4e1eb; --accent: #00d9ff; --error: #ff6b6b; --muted: #6e6a7c; --border: #3d3852; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'IBM Plex Sans', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; padding: 40px 20px; }
    .container { max-width: 700px; margin: 0 auto; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; overflow: hidden; }
    .header { padding: 24px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 16px; }
    .icon { width: 48px; height: 48px; background: linear-gradient(135deg, var(--error), #ff8585); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; }
    .body { padding: 24px; }
    .error-box { background: rgba(255, 107, 107, 0.1); border: 1px solid rgba(255, 107, 107, 0.3); border-radius: 12px; padding: 20px; }
    .error-title { font-weight: 600; color: var(--error); margin-bottom: 8px; }
    .error-filter { font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: var(--accent); margin-bottom: 12px; }
    .error-message { font-size: 0.9rem; color: var(--muted); word-break: break-all; }
    .footer { padding: 16px 24px; background: #1f1b2b; border-top: 1px solid var(--border); text-align: center; font-size: 0.8rem; color: var(--muted); }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="header">
        <div class="icon">⚠️</div>
        <h1>LDAP Search Error</h1>
      </div>
      <div class="body">
        <div class="error-box">
          <div class="error-title">Connection or Query Failed</div>
          <div class="error-filter">Filter: ${filter.replace("<", "&lt;").replace(">", "&gt;")}</div>
          <div class="error-message">${if (error != null) error.take(500).replace("<", "&lt;").replace(">", "&gt;") else "Unknown error"}</div>
        </div>
      </div>
      <div class="footer">LDAP Directory Service • pt.tecnico.dsi:ldap</div>
    </div>
  </div>
</body>
</html>"""
  }
}
