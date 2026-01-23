package io.snyk.woof.server

import scala.collection.immutable.List
import javax.ws.rs._
import javax.ws.rs.core.MediaType

@Path("resources")
@Produces(Array(MediaType.TEXT_HTML))
class ResourceAllocationResource {

  private def usedMemoryMB(): Long = {
    val runtime = Runtime.getRuntime
    (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024)
  }

  private def validateCount(count: Int): Int = {
    if (count < 0) {
      println(s"Warning: Count is negative: $count")
    }
    count
  }

  private def validateCountRange(count: Int): Int = {
    if (count > 1000000) {
      println(s"Warning: Count exceeds recommended maximum: $count")
    }
    count
  }

  @GET
  @Path("allocate")
  //SOURCE
  def allocateResources(@QueryParam("count") count: Int): String = {
    val validatedCount = validateCount(count)
    val checkedCount = validateCountRange(validatedCount)

    val memBefore = usedMemoryMB()
    val startTime = System.currentTimeMillis()

    //CWE 400
    //SINK
    val resources = List.fill(checkedCount)("resource-item")

    val endTime = System.currentTimeMillis()
    val memAfter = usedMemoryMB()
    val memDelta = memAfter - memBefore
    val duration = endTime - startTime

    System.setProperty("LAST_ALLOCATION_COUNT", checkedCount.toString)
    System.setProperty("LAST_ALLOCATION_DURATION", s"${duration}ms")
    System.setProperty("LAST_ALLOCATION_MEM_DELTA", s"${memDelta}MB")

    s"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Resource Allocation</title>
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
    .progress-section { margin-top: 20px; }
    .progress-header { display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 0.85rem; }
    .progress-bar { height: 8px; background: #e1e4e8; border-radius: 4px; overflow: hidden; }
    .progress-fill { height: 100%; background: linear-gradient(90deg, var(--success), #2da44e); border-radius: 4px; animation: fill 1s ease-out; }
    @keyframes fill { from { width: 0; } }
    .status-badge { display: inline-flex; align-items: center; gap: 6px; background: #dafbe1; color: var(--success); padding: 6px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 500; margin-top: 20px; }
    .status-dot { width: 6px; height: 6px; background: var(--success); border-radius: 50%; }
    .footer { padding: 16px 24px; background: #f6f8fa; border-top: 1px solid var(--border); font-size: 0.8rem; color: var(--muted); text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="header">
        <div class="icon">📊</div>
        <h1>Resource Allocation Summary</h1>
      </div>
      <div class="body">
        <div class="stats">
          <div class="stat">
            <div class="stat-value">${resources.size}</div>
            <div class="stat-label">Items Allocated</div>
          </div>
          <div class="stat">
            <div class="stat-value">${duration}ms</div>
            <div class="stat-label">Duration</div>
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
            <div class="stat-value">${if (duration > 0) (resources.size / duration) else resources.size}/ms</div>
            <div class="stat-label">Throughput</div>
          </div>
        </div>
        <div class="progress-section">
          <div class="progress-header">
            <span>Allocation Progress</span>
            <span>100%</span>
          </div>
          <div class="progress-bar">
            <div class="progress-fill" style="width: 100%"></div>
          </div>
        </div>
        <div class="status-badge">
          <span class="status-dot"></span>
          Allocation completed successfully
        </div>
      </div>
      <div class="footer">Resource Manager v1.5 • Memory Pool Service</div>
    </div>
  </div>
</body>
</html>"""
  }
}


