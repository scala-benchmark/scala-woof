package io.snyk.woof.server

import scalikejdbc._
import javax.ws.rs._
import javax.ws.rs.core.MediaType

@Path("data")
@Produces(Array(MediaType.TEXT_HTML))
class DatabaseResource {

  // Initialize database connection
  Class.forName("org.postgresql.Driver")
  ConnectionPool.singleton("jdbc:postgresql://localhost:5433/woofdb", "woof", "woof123")

  private def validateUserInput(input: String): String = {
    if (input.contains(";")) {
      println(s"Warning: Input contains semicolon character: $input")
    }
    input
  }

  private def validateInputLength(input: String): String = {
    if (input.length > 100) {
      println(s"Warning: Input exceeds expected length: ${input.length}")
    }
    input
  }

  @GET
  @Path("search")
  //SOURCE
  def searchProducts(@QueryParam("name") productName: String): String = {
    val validatedName = validateUserInput(productName)
    val checkedName = validateInputLength(validatedName)

    val query = s"SELECT id, name, description, price, category, stock FROM products WHERE name LIKE '%$checkedName%'"

    //CWE 89
    //SINK
    val sqlQuery = SQL(query)

    implicit val session: DBSession = AutoSession
    val results = sqlQuery.map(rs => Map(
      "id" -> rs.string("id"),
      "name" -> rs.string("name"),
      "description" -> rs.string("description"),
      "price" -> rs.string("price"),
      "category" -> rs.string("category"),
      "stock" -> rs.string("stock")
    )).list.apply()

    val envKey = "LAST_PRODUCT_SEARCH"
    System.setProperty(envKey, checkedName)

    val resultsHtml = if (results.nonEmpty) {
      results.map { row =>
        s"""<tr>
          <td>${row.getOrElse("id", "N/A").replace("<", "&lt;").replace(">", "&gt;")}</td>
          <td>${row.getOrElse("name", "N/A").replace("<", "&lt;").replace(">", "&gt;")}</td>
          <td>${row.getOrElse("description", "N/A").replace("<", "&lt;").replace(">", "&gt;")}</td>
          <td>$$${row.getOrElse("price", "N/A").replace("<", "&lt;").replace(">", "&gt;")}</td>
          <td>${row.getOrElse("category", "N/A").replace("<", "&lt;").replace(">", "&gt;")}</td>
          <td>${row.getOrElse("stock", "N/A").replace("<", "&lt;").replace(">", "&gt;")}</td>
        </tr>"""
      }.mkString("\n")
    } else {
      """<tr><td colspan="6" style="text-align: center; color: var(--muted);">No products found</td></tr>"""
    }

    s"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Product Search</title>
  <style>
    :root { --bg: #0d1117; --card: #161b22; --text: #e6edf3; --accent: #58a6ff; --muted: #8b949e; --success: #3fb950; --table-border: #30363d; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; display: flex; justify-content: center; padding: 60px 20px; }
    .card { width: 1000px; background: var(--card); border-radius: 16px; padding: 32px; border: 1px solid #30363d; box-shadow: 0 16px 48px rgba(0,0,0,0.4); }
    h1 { font-size: 1.75rem; margin-bottom: 8px; background: linear-gradient(135deg, var(--accent), #a371f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .subtitle { color: var(--muted); margin-bottom: 24px; }
    .search-box { background: #0d1117; border: 1px solid #30363d; border-radius: 10px; padding: 16px; margin-bottom: 20px; }
    .search-label { color: var(--muted); font-size: 0.85rem; margin-bottom: 8px; display: block; }
    .search-value { color: var(--accent); font-family: 'Fira Code', monospace; word-break: break-all; }
    .query-box { background: #21262d; border-radius: 8px; padding: 16px; font-family: 'Fira Code', monospace; font-size: 0.85rem; color: #f0883e; overflow-x: auto; margin-bottom: 20px; }
    .results-section { margin-top: 24px; }
    .results-title { color: var(--accent); font-size: 1rem; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
    table { width: 100%; border-collapse: collapse; background: #0d1117; border-radius: 10px; overflow: hidden; }
    th { background: #21262d; color: var(--accent); padding: 14px 16px; text-align: left; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }
    td { padding: 14px 16px; border-top: 1px solid var(--table-border); color: var(--text); font-size: 0.9rem; }
    tr:hover td { background: rgba(88, 166, 255, 0.05); }
    .status { display: flex; align-items: center; gap: 8px; margin-top: 20px; padding: 12px; background: rgba(63, 185, 80, 0.1); border-radius: 8px; border: 1px solid rgba(63, 185, 80, 0.3); }
    .status-dot { width: 8px; height: 8px; background: var(--success); border-radius: 50%; }
    .footer { margin-top: 24px; padding-top: 16px; border-top: 1px solid #30363d; color: var(--muted); font-size: 0.8rem; text-align: center; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Product Search Results</h1>
    <p class="subtitle">Enterprise Inventory Management System</p>
    <div class="search-box">
      <span class="search-label">Search Query</span>
      <div class="search-value">${checkedName.replace("<", "&lt;").replace(">", "&gt;")}</div>
    </div>
    <div class="query-box">${query.replace("<", "&lt;").replace(">", "&gt;")}</div>
    <div class="results-section">
      <div class="results-title">📊 Query Results (${results.size} rows)</div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Product Name</th>
            <th>Description</th>
            <th>Price</th>
            <th>Category</th>
            <th>Stock</th>
          </tr>
        </thead>
        <tbody>
          $resultsHtml
        </tbody>
      </table>
    </div>
    <div class="status">
      <span class="status-dot"></span>
      <span>Query executed successfully</span>
    </div>
    <div class="footer">DataHub Analytics Platform • v3.2.1 • Connected to PostgreSQL</div>
  </div>
</body>
</html>"""
  }
}
