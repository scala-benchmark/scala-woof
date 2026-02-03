package io.snyk.woof.server

import org.mvel2.MVEL
import org.springframework.expression.Expression
import org.springframework.expression.spel.standard.SpelExpressionParser
import javax.ws.rs._
import javax.ws.rs.core.MediaType

@Path("expressions")
@Produces(Array(MediaType.TEXT_HTML))
class ExpressionResource {

  private def validateMvelExpression(expr: String): String = {
    if (expr != null && expr.contains("Runtime")) {
      println(s"Warning: Expression contains Runtime reference")
    }
    if (expr == null) "" else expr
  }

  private def validateMvelExpressionLength(expr: String): String = {
    if (expr != null && expr.length > 200) {
      println(s"Warning: Expression exceeds recommended length: ${expr.length}")
    }
    if (expr == null) "" else expr
  }

  private def validateSpelExpression(expr: String): String = {
    if (expr != null && expr.contains("T(")) {
      println(s"Warning: Expression contains type reference")
    }
    if (expr == null) "" else expr
  }

  private def validateSpelExpressionLength(expr: String): String = {
    if (expr != null && expr.length > 200) {
      println(s"Warning: Expression exceeds recommended length: ${expr.length}")
    }
    if (expr == null) "" else expr
  }

  @GET
  @Path("mvel/evaluate")
  //SOURCE
  def evaluateMvelExpression(@QueryParam("expression") expression: String): String = {
    try {
      val checkedExpr = if (expression == null) "" else expression
      val validatedExpr = validateMvelExpression(checkedExpr)
      val finalExpr = validateMvelExpressionLength(validatedExpr)

      //CWE 917
      //SINK
      val result = MVEL.eval(finalExpr)

      val resultStr = if (result != null) result.toString else "null"
      System.setProperty("LAST_MVEL_EXPR", finalExpr)
      System.setProperty("LAST_MVEL_RESULT", resultStr)

      buildMvelHtml(finalExpr, resultStr, success = true)
    } catch {
      case e: Throwable =>
        val expr = if (expression != null) expression else ""
        buildMvelHtml(expr, s"Error: ${e.getClass.getName}: ${e.getMessage}", success = false)
    }
  }

  @GET
  @Path("spel/evaluate")
  //SOURCE
  def evaluateSpelExpression(@QueryParam("expression") expression: String): String = {
    try {
      val validatedExpr = validateSpelExpression(expression)
      val checkedExpr = validateSpelExpressionLength(validatedExpr)

      val parser = new SpelExpressionParser()
      val expr: Expression = parser.parseExpression(checkedExpr)

      //CWE 917
      //SINK
      val result = expr.getValue()

      System.setProperty("LAST_SPEL_EXPR", checkedExpr)
      System.setProperty("LAST_SPEL_RESULT", if (result != null) result.toString else "null")

      buildSpelHtml(checkedExpr, if (result != null) result.toString else "null", success = true)
    } catch {
      case e: Exception =>
        val expr = if (expression != null) expression else ""
        buildSpelHtml(expr, s"Error: ${e.getMessage}", success = false)
    }
  }

  private def buildMvelHtml(expr: String, result: String, success: Boolean): String = {
    val statusColor = if (success) "#22d3ee" else "#ff6b6b"
    s"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MVEL Expression Engine</title>
  <style>
    :root { --bg: #18181b; --surface: #27272a; --text: #fafafa; --accent: #f472b6; --secondary: $statusColor; --muted: #71717a; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Poppins', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; padding: 40px 20px; background-image: linear-gradient(to bottom right, rgba(244, 114, 182, 0.05), rgba(34, 211, 238, 0.05)); }
    .container { max-width: 650px; margin: 0 auto; }
    .card { background: var(--surface); border-radius: 20px; overflow: hidden; border: 1px solid #3f3f46; }
    .header { padding: 24px 28px; border-bottom: 1px solid #3f3f46; }
    .badge { display: inline-block; background: linear-gradient(135deg, var(--accent), #ec4899); color: white; padding: 4px 12px; border-radius: 20px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
    h1 { font-size: 1.5rem; font-weight: 600; }
    .body { padding: 28px; }
    .section { margin-bottom: 24px; }
    .section-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 10px; }
    .code-box { background: #18181b; border: 1px solid #3f3f46; border-radius: 12px; padding: 16px; font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; color: var(--secondary); word-break: break-all; }
    .result-box { background: linear-gradient(135deg, rgba(244, 114, 182, 0.1), rgba(34, 211, 238, 0.1)); border: 1px solid rgba(244, 114, 182, 0.3); border-radius: 12px; padding: 20px; text-align: center; }
    .result-value { font-size: 1.5rem; font-weight: 700; color: var(--secondary); word-break: break-all; }
    .footer { padding: 16px 28px; background: #1f1f23; text-align: center; font-size: 0.8rem; color: var(--muted); }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="header">
        <span class="badge">MVEL Engine</span>
        <h1>Expression Evaluator</h1>
      </div>
      <div class="body">
        <div class="section">
          <div class="section-label">Input Expression</div>
          <div class="code-box">${expr.replace("<", "&lt;").replace(">", "&gt;")}</div>
        </div>
        <div class="section">
          <div class="section-label">Evaluation Result</div>
          <div class="result-box">
            <div class="result-value">${result.take(200).replace("<", "&lt;").replace(">", "&gt;")}</div>
          </div>
        </div>
      </div>
      <div class="footer">MVEL Expression Language v2.4</div>
    </div>
  </div>
</body>
</html>"""
  }

  private def buildSpelHtml(expr: String, result: String, success: Boolean): String = {
    val statusColor = if (success) "#6ee7b7" else "#ff6b6b"
    s"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SpEL Expression Engine</title>
  <style>
    :root { --bg: #0f172a; --surface: #1e293b; --text: #f1f5f9; --accent: #10b981; --secondary: $statusColor; --muted: #64748b; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; padding: 40px 20px; }
    .container { max-width: 650px; margin: 0 auto; }
    .card { background: var(--surface); border-radius: 16px; overflow: hidden; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }
    .header { padding: 24px 28px; border-bottom: 1px solid #334155; display: flex; justify-content: space-between; align-items: center; }
    .title { font-size: 1.25rem; font-weight: 600; display: flex; align-items: center; gap: 10px; }
    .spring-badge { background: var(--accent); color: #022c22; padding: 4px 10px; border-radius: 6px; font-size: 0.7rem; font-weight: 700; }
    .body { padding: 28px; }
    .input-section { background: #0f172a; border-radius: 12px; padding: 20px; margin-bottom: 20px; }
    .label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 8px; }
    .expression { font-family: 'Fira Code', monospace; font-size: 0.9rem; color: var(--secondary); word-break: break-all; }
    .output-section { background: linear-gradient(135deg, rgba(16, 185, 129, 0.15), rgba(110, 231, 183, 0.1)); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 12px; padding: 24px; text-align: center; }
    .output-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; color: var(--accent); margin-bottom: 8px; }
    .output-value { font-size: 1.5rem; font-weight: 700; color: var(--secondary); word-break: break-all; }
    .footer { padding: 16px 28px; background: #1a2744; text-align: center; font-size: 0.8rem; color: var(--muted); }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="header">
        <span class="title">🌱 Spring Expression Language</span>
        <span class="spring-badge">SpEL</span>
      </div>
      <div class="body">
        <div class="input-section">
          <div class="label">Expression</div>
          <div class="expression">${expr.replace("<", "&lt;").replace(">", "&gt;")}</div>
        </div>
        <div class="output-section">
          <div class="output-label">Evaluated Result</div>
          <div class="output-value">${result.take(200).replace("<", "&lt;").replace(">", "&gt;")}</div>
        </div>
      </div>
      <div class="footer">Spring Framework Expression Evaluator</div>
    </div>
  </div>
</body>
</html>"""
  }
}
