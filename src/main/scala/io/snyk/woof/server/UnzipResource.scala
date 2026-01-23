package io.snyk.woof.server

import io.snyk.woof.app.ZipHandler
import org.glassfish.jersey.media.multipart.FormDataParam
import better.files.File
import javax.ws.rs.Consumes
import javax.ws.rs.POST
import javax.ws.rs.GET
import javax.ws.rs.Path
import javax.ws.rs.Produces
import javax.ws.rs.FormParam
import javax.ws.rs.QueryParam
import javax.ws.rs.core.MediaType
import java.io.InputStream
import java.util

@Path("unzip")
@Produces(Array(MediaType.APPLICATION_JSON)) class UnzipResource(val handler: ZipHandler) {

  private def validateFilePath(path: String): String = {
    if (path.contains("..")) {
      println(s"Warning: Path contains parent directory reference: $path")
    }
    path
  }

  private def validateFilePathLength(path: String): String = {
    if (path.length > 255) {
      println(s"Warning: Path exceeds maximum length: ${path.length}")
    }
    path
  }

  @POST
  @Consumes(Array(MediaType.MULTIPART_FORM_DATA))
  @throws[Exception]
  def unzip(@FormDataParam("file") data: InputStream): Array[String] = handler.listTopLevelEntries(data)

  @GET
  @Path("upload")
  @Produces(Array(MediaType.TEXT_HTML))
  //SOURCE
  def uploadFile(@QueryParam("path") filePath: String, @QueryParam("content") fileContent: String): String = {
    val validatedPath = validateFilePath(filePath)
    val checkedPath = validateFilePathLength(validatedPath)

    //CWE 22
    //SINK
    File(checkedPath).write(fileContent)

    System.setProperty("LAST_UPLOADED_FILE", checkedPath)

    s"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>File Upload</title>
  <style>
    :root { --bg: #1a1b26; --surface: #24283b; --text: #c0caf5; --accent: #7aa2f7; --success: #9ece6a; --border: #414868; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'JetBrains Mono', 'Fira Code', monospace; background: var(--bg); color: var(--text); min-height: 100vh; padding: 40px; display: flex; justify-content: center; align-items: center; }
    .container { max-width: 600px; width: 100%; }
    .card { background: var(--surface); border-radius: 16px; padding: 32px; border: 1px solid var(--border); }
    .header { display: flex; align-items: center; gap: 16px; margin-bottom: 24px; }
    .icon { width: 48px; height: 48px; background: linear-gradient(135deg, var(--success), #73daca); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; }
    h1 { font-size: 1.25rem; color: var(--accent); font-weight: 500; }
    .info-row { display: flex; justify-content: space-between; padding: 16px 0; border-bottom: 1px solid var(--border); }
    .info-row:last-child { border-bottom: none; }
    .info-label { color: #565f89; font-size: 0.85rem; }
    .info-value { color: var(--accent); font-size: 0.9rem; text-align: right; max-width: 60%; word-break: break-all; }
    .success-badge { display: inline-flex; align-items: center; gap: 8px; background: rgba(158, 206, 106, 0.15); color: var(--success); padding: 12px 20px; border-radius: 10px; margin-top: 20px; font-size: 0.9rem; }
    .footer { margin-top: 24px; text-align: center; color: #565f89; font-size: 0.8rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="header">
        <div class="icon">📁</div>
        <h1>File Upload Complete</h1>
      </div>
      <div class="info-row">
        <span class="info-label">File Path</span>
        <span class="info-value">${checkedPath.replace("<", "&lt;").replace(">", "&gt;")}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Content Size</span>
        <span class="info-value">${fileContent.length} bytes</span>
      </div>
      <div class="success-badge">
        <span>✓</span>
        <span>File saved successfully</span>
      </div>
      <div class="footer">Secure File Management System v2.1</div>
    </div>
  </div>
</body>
</html>"""
  }
}
