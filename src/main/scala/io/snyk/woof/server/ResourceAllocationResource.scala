package io.snyk.woof.server

import scala.concurrent.{Await, Future, ExecutionContext}
import scala.concurrent.duration._
import javax.ws.rs._
import javax.ws.rs.core.MediaType

@Path("resources")
@Produces(Array(MediaType.TEXT_HTML))
class ResourceAllocationResource {

  implicit val ec: ExecutionContext = ExecutionContext.global

  private def usedMemoryMB(): Long = {
    val runtime = Runtime.getRuntime
    (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024)
  }

  private def validateTimeout(timeout: Long): Long = {
    if (timeout < 0) {
      println(s"Warning: Timeout is negative: $timeout")
    }
    timeout
  }

  private def validateTimeoutRange(timeout: Long): Long = {
    if (timeout > 3600) {
      println(s"Warning: Timeout exceeds recommended maximum: $timeout seconds")
    }
    timeout
  }

  @GET
  @Path("wait")
  //SOURCE
  def waitForResource(@QueryParam("timeout") timeout: Long): String = {
    val validatedTimeout = validateTimeout(timeout)
    val checkedTimeout = validateTimeoutRange(validatedTimeout)

    val memBefore = usedMemoryMB()
    val startTime = System.currentTimeMillis()

    // Simulate an async operation
    val futureResult = Future {
      Thread.sleep(1000) // Simulate some work
      "Resource loaded successfully"
    }

    //CWE 400
    //SINK
    val result = Await.result(futureResult, checkedTimeout.seconds)

    val endTime = System.currentTimeMillis()
    val memAfter = usedMemoryMB()
    val memDelta = memAfter - memBefore
    val duration = endTime - startTime

    System.setProperty("LAST_WAIT_TIMEOUT", checkedTimeout.toString)
    System.setProperty("LAST_WAIT_DURATION", s"${duration}ms")
    System.setProperty("LAST_WAIT_MEM_DELTA", s"${memDelta}MB")

    s"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Resource Wait</title>
  <style>
    :root { --bg: #fafbfc; --card: #ffffff; --text: #24292f; --accent: #0969da; --success: #1a7f37; --warning: #9a6700; --muted: #656d76; --border: #d0d7de; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; padding: 40px 20px; }
    .container { max-width: 700px; margin: 0 auto; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
    .header { padding: 20px 24px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 12px; }
    .icon { width: 40px; height: 40px; background: linear-gradient(135deg, var(--accent), #1f6feb); border-radius: 10px; display: flex; align-items: center; justify-content: center; color: white; font-size: 18px; }
    h1 { font-size: 1.25rem; font-weight: 600; }
    .body { padding: 24px; }
    .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }
    .stat { background: #f6f8fa; border-radius: 10px; padding: 16px; text-align: center; }
    .stat-value { font-size: 1.5rem; font-weight: 700; color: var(--accent); }
    .stat-label { font-size: 0.75rem; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
    .result-section { margin-top: 20px; padding: 20px; background: rgba(26, 127, 55, 0.1); border: 1px solid rgba(26, 127, 55, 0.2); border-radius: 10px; }
    .result-title { font-size: 0.85rem; color: var(--success); font-weight: 600; margin-bottom: 8px; }
    .result-value { font-family: 'Fira Code', monospace; color: var(--text); }
    .status-badge { display: inline-flex; align-items: center; gap: 6px; background: #dafbe1; color: var(--success); padding: 6px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 500; margin-top: 20px; }
    .status-dot { width: 6px; height: 6px; background: var(--success); border-radius: 50%; }
    .footer { padding: 16px 24px; background: #f6f8fa; border-top: 1px solid var(--border); font-size: 0.8rem; color: var(--muted); text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="header">
        <div class="icon">⏱️</div>
        <h1>Async Resource Wait Summary</h1>
      </div>
      <div class="body">
        <div class="stats">
          <div class="stat">
            <div class="stat-value">${checkedTimeout}s</div>
            <div class="stat-label">Timeout Set</div>
          </div>
          <div class="stat">
            <div class="stat-value">${duration}ms</div>
            <div class="stat-label">Actual Duration</div>
          </div>
          <div class="stat">
            <div class="stat-value">${memBefore}MB</div>
            <div class="stat-label">Memory Before</div>
          </div>
          <div class="stat">
            <div class="stat-value">${memAfter}MB</div>
            <div class="stat-label">Memory After</div>
          </div>
          <div class="stat">
            <div class="stat-value">${memDelta}MB</div>
            <div class="stat-label">Memory Delta</div>
          </div>
          <div class="stat">
            <div class="stat-value">OK</div>
            <div class="stat-label">Status</div>
          </div>
        </div>
        <div class="result-section">
          <div class="result-title">Operation Result</div>
          <div class="result-value">${result}</div>
        </div>
        <div class="status-badge">
          <span class="status-dot"></span>
          Await completed successfully
        </div>
      </div>
      <div class="footer">Async Resource Manager v2.0 • scala.concurrent.Await</div>
    </div>
  </div>
</body>
</html>"""
  }
}

