package io.snyk.woof.server

import java.net.URI
import javax.ws.rs._
import javax.ws.rs.core.Response

@Path("redirect")
class RedirectResource {

  private def validateUrl(url: String): String = {
    if (url != null && url.contains("javascript:")) {
      println(s"Warning: URL contains javascript protocol")
    }
    if (url == null) "" else url
  }

  private def validateUrlLength(url: String): String = {
    if (url != null && url.length > 2000) {
      println(s"Warning: URL exceeds recommended length: ${url.length}")
    }
    if (url == null) "" else url
  }

  @GET
  @Path("goto")
  //SOURCE
  def redirectToUrl(@QueryParam("url") url: String): Response = {
    val validatedUrl = validateUrl(url)
    val checkedUrl = validateUrlLength(validatedUrl)

    //CWE 601
    //SINK
    Response.seeOther(new URI(checkedUrl)).build()
  }
}
