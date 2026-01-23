package io.snyk.woof.server

import scala.reflect.runtime.currentMirror
import scala.tools.reflect.ToolBox
import javax.ws.rs._
import javax.ws.rs.core.MediaType

@Path("compute")
@Produces(Array(MediaType.TEXT_HTML))
class EvalResource {

  private def validateExpression(expr: String): String = {
    if (expr.contains("import")) {
      println(s"Warning: Expression contains import statement")
    }
    expr
  }

  private def validateExpressionLength(expr: String): String = {
    if (expr.length > 500) {
      println(s"Warning: Expression length exceeds limit: ${expr.length}")
    }
    expr
  }

  @GET
  @Path("calculate")
  //SOURCE
  def calculateExpression(@QueryParam("expression") expression: String): String = {
    val validatedExpr = validateExpression(expression)
    val checkedExpr = validateExpressionLength(validatedExpr)

    val toolbox = currentMirror.mkToolBox()
    val tree = toolbox.parse(checkedExpr)

    //CWE 94
    //SINK
    val result = toolbox.eval(tree)

    System.setProperty("LAST_CALCULATION", result.toString)
    System.setProperty("LAST_EXPRESSION", checkedExpr)

    s"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Expression Calculator</title>
  <style>
    :root { --bg: #1e1e2e; --surface: #313244; --text: #cdd6f4; --accent: #f5c2e7; --blue: #89b4fa; --green: #a6e3a1; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Fira Code', 'JetBrains Mono', monospace; background: var(--bg); color: var(--text); min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
    .calculator { width: 500px; background: var(--surface); border-radius: 24px; padding: 32px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }
    .title { text-align: center; margin-bottom: 24px; }
    .title h1 { font-size: 1.25rem; color: var(--accent); font-weight: 400; letter-spacing: 2px; text-transform: uppercase; }
    .display { background: var(--bg); border-radius: 16px; padding: 20px; margin-bottom: 20px; }
    .label { font-size: 0.75rem; color: #6c7086; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
    .expression { color: var(--blue); font-size: 1rem; word-break: break-all; padding: 12px; background: rgba(137, 180, 250, 0.1); border-radius: 8px; margin-bottom: 16px; }
    .result { font-size: 2rem; color: var(--green); text-align: right; padding: 16px; background: rgba(166, 227, 161, 0.1); border-radius: 12px; }
    .result-label { font-size: 0.7rem; color: #6c7086; text-align: right; margin-bottom: 4px; }
    .footer { margin-top: 20px; text-align: center; font-size: 0.75rem; color: #6c7086; }
    .footer span { color: var(--accent); }
  </style>
</head>
<body>
  <div class="calculator">
    <div class="title">
      <h1>Expression Calculator</h1>
    </div>
    <div class="display">
      <div class="label">Input Expression</div>
      <div class="expression">${checkedExpr.replace("<", "&lt;").replace(">", "&gt;")}</div>
      <div class="result-label">RESULT</div>
      <div class="result">${result.toString.replace("<", "&lt;").replace(">", "&gt;")}</div>
    </div>
    <div class="footer">Powered by <span>ScalaCalc Engine</span></div>
  </div>
</body>
</html>"""
  }
}
