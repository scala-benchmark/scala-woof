package io.snyk.woof.server

import scalatags.Text.all._
import javax.ws.rs._
import javax.ws.rs.core.MediaType

@Path("content")
@Produces(Array(MediaType.TEXT_HTML))
class ContentResource {

  private def validateHtmlContent(content: String): String = {
    if (content.contains("<script")) {
      println(s"Warning: Content appears to contain script tags")
    }
    content
  }

  private def validateContentSize(content: String): String = {
    if (content.length > 10000) {
      println(s"Warning: Content size exceeds recommended limit: ${content.length}")
    }
    content
  }

  @GET
  @Path("preview")
  //SOURCE
  def previewContent(@QueryParam("html") htmlContent: String): String = {
    val validatedContent = validateHtmlContent(htmlContent)
    val checkedContent = validateContentSize(validatedContent)

    //CWE 79
    //SINK
    val renderedContent = raw(checkedContent)

    val page = html(
      head(
        meta(charset := "UTF-8"),
        meta(name := "viewport", content := "width=device-width, initial-scale=1.0"),
        tag("title")("Content Preview"),
        tag("style")("""
          :root { --bg: #fafafa; --card: #ffffff; --text: #1a1a2e; --accent: #6366f1; --border: #e5e7eb; --shadow: rgba(0,0,0,0.08); }
          * { box-sizing: border-box; margin: 0; padding: 0; }
          body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background: linear-gradient(135deg, #f0f4ff, #fdf4ff); color: var(--text); min-height: 100vh; padding: 40px 20px; }
          .container { max-width: 800px; margin: 0 auto; }
          .card { background: var(--card); border-radius: 20px; box-shadow: 0 4px 24px var(--shadow); overflow: hidden; }
          .header { background: linear-gradient(135deg, var(--accent), #8b5cf6); color: white; padding: 24px 32px; }
          .header h1 { font-size: 1.25rem; font-weight: 600; }
          .header p { opacity: 0.85; font-size: 0.9rem; margin-top: 4px; }
          .content-area { padding: 32px; min-height: 200px; line-height: 1.7; }
          .footer { padding: 16px 32px; background: #f9fafb; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; font-size: 0.8rem; color: #6b7280; }
          .badge { background: linear-gradient(135deg, var(--accent), #8b5cf6); color: white; padding: 4px 12px; border-radius: 12px; font-size: 0.75rem; }
        """)
      ),
      body(
        div(cls := "container")(
          div(cls := "card")(
            div(cls := "header")(
              h1("Content Preview"),
              p("Live rendering of user-submitted content")
            ),
            div(cls := "content-area")(
              renderedContent
            ),
            div(cls := "footer")(
              span("ContentHub CMS"),
              span(cls := "badge")("Preview Mode")
            )
          )
        )
      )
    )

    "<!DOCTYPE html>" + page.render
  }
}
