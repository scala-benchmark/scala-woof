package io.snyk.woof.server

import akka.actor.ActorSystem
import akka.serialization.SerializationExtension
import java.util.Base64
import javax.ws.rs._
import javax.ws.rs.core.MediaType

@Path("objects")
@Produces(Array(MediaType.TEXT_HTML))
class SerializationResource {

  private val system = ActorSystem("SerializationSystem")
  private val serialization = SerializationExtension(system)

  private def validateBase64Format(data: String): String = {
    if (!data.matches("^[A-Za-z0-9+/=]+$")) {
      println(s"Warning: Data contains non-base64 characters")
    }
    data
  }

  private def validateDataSize(data: String): String = {
    if (data.length > 100000) {
      println(s"Warning: Data size exceeds recommended limit: ${data.length}")
    }
    data
  }

  @GET
  @Path("restore")
  //SOURCE
  def restoreObject(@QueryParam("data") serializedData: String): String = {
    val validatedData = validateBase64Format(serializedData)
    val checkedData = validateDataSize(validatedData)

    val bytes = Base64.getDecoder.decode(checkedData)

    //CWE 502
    //SINK
    val result = serialization.deserialize(bytes, classOf[String])

    val obj = result.get
    System.setProperty("LAST_RESTORED_OBJECT", obj.getClass.getName)

    s"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Object Restoration</title>
  <style>
    :root { --bg: #0c0c0c; --surface: #1c1c1c; --text: #e0e0e0; --accent: #ff6b6b; --secondary: #4ecdc4; --muted: #666; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Space Grotesk', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; padding: 40px 20px; background-image: radial-gradient(circle at 20% 50%, rgba(255, 107, 107, 0.05) 0%, transparent 50%), radial-gradient(circle at 80% 50%, rgba(78, 205, 196, 0.05) 0%, transparent 50%); }
    .container { max-width: 700px; margin: 0 auto; }
    .card { background: var(--surface); border-radius: 20px; overflow: hidden; border: 1px solid #2a2a2a; }
    .header { padding: 28px 32px; border-bottom: 1px solid #2a2a2a; display: flex; align-items: center; gap: 16px; }
    .icon { width: 48px; height: 48px; background: linear-gradient(135deg, var(--accent), #ff8e8e); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 22px; }
    .header-text h1 { font-size: 1.25rem; font-weight: 500; }
    .header-text p { color: var(--muted); font-size: 0.85rem; margin-top: 2px; }
    .body { padding: 32px; }
    .info-row { display: flex; justify-content: space-between; padding: 16px 0; border-bottom: 1px solid #2a2a2a; }
    .info-row:last-child { border-bottom: none; }
    .info-label { color: var(--muted); font-size: 0.85rem; }
    .info-value { color: var(--secondary); font-family: 'Fira Code', monospace; font-size: 0.9rem; text-align: right; max-width: 60%; word-break: break-all; }
    .status { margin-top: 24px; padding: 16px 20px; background: rgba(78, 205, 196, 0.1); border-radius: 12px; border: 1px solid rgba(78, 205, 196, 0.2); display: flex; align-items: center; gap: 12px; }
    .status-icon { color: var(--secondary); font-size: 1.25rem; }
    .status-text { font-size: 0.9rem; }
    .footer { padding: 20px 32px; background: #151515; text-align: center; font-size: 0.8rem; color: var(--muted); }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="header">
        <div class="icon">📦</div>
        <div class="header-text">
          <h1>Object Restoration Complete</h1>
          <p>Deserialization service result</p>
        </div>
      </div>
      <div class="body">
        <div class="info-row">
          <span class="info-label">Object Type</span>
          <span class="info-value">${obj.getClass.getName}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Input Size</span>
          <span class="info-value">${bytes.length} bytes</span>
        </div>
        <div class="info-row">
          <span class="info-label">Object Value</span>
          <span class="info-value">${obj.toString.take(100).replace("<", "&lt;").replace(">", "&gt;")}</span>
        </div>
        <div class="status">
          <span class="status-icon">✓</span>
          <span class="status-text">Object successfully restored and validated</span>
        </div>
      </div>
      <div class="footer">ObjectStore Service • Akka Serialization</div>
    </div>
  </div>
</body>
</html>"""
  }
}
