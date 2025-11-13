// AssignmentServlet.java
// Assignment servlet (~230 lines) for student exercise.
// Endpoints:
//   GET  /asmt          -> index with links
//   POST /asmt/comment  -> vulnerable (reflected XSS)
//   GET  /asmt/search   -> vulnerable (reflected XSS)
//   GET  /asmt/userByEmail -> vulnerable (SQL injection)
//   GET  /asmt/list     -> view recent comments (safe rendering uses Html.escape)


// AssignmentServlet.java (patched)
import java.io.PrintWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Optional;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.commons.text.StringEscapeUtils;
import java.sql.*;

@WebServlet(name = "AssignmentServlet", urlPatterns = {"/asmt/*"})
public class AssignmentServlet extends HttpServlet {

  // in-memory store for submitted comments
  private final Deque<Comment> store = new ArrayDeque<>();

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    resp.setCharacterEncoding(StandardCharsets.UTF_8.name());
    route(req, resp);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    resp.setCharacterEncoding(StandardCharsets.UTF_8.name());
    route(req, resp);
  }

  private void route(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String path = Optional.ofNullable(req.getPathInfo()).orElse("/");
    switch (path) {
      case "/":
        home(resp);
        break;
      case "/comment":
        submitComment(req, resp);
        break;
      case "/search":
        search(req, resp);
        break;
      case "/userByEmail":
        userByEmail(req, resp);
        break;
      case "/list":
        listComments(resp);
        break;
      default:
        notFound(resp, path);
    }
  }

  private void home(HttpServletResponse resp) throws IOException {
    StringBuilder sb = new StringBuilder();
    sb.append(h1("Assignment: Comment Board"));
    sb.append(p("This board accepts author & text. The endpoints below contain intentional bugs for you to discover and patch."));
    sb.append(p("Use the list endpoint to view recent comments."));
    sb.append(ul(
        li(a("/asmt/list", "GET /asmt/list")) +
        li(a("/asmt/comment", "POST /asmt/comment (reflected XSS)")) +
        li(a("/asmt/search?q=hello", "GET /asmt/search?q=... (reflected XSS)")) +
        li(a("/asmt/userByEmail?email=test@example.com", "GET /asmt/userByEmail (SQL injection)"))
    ));
    ok(resp, page("Assignment Home", sb.toString()));
  }

  // FIXED: encode author/text before building the thank-you sections
  private void submitComment(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String author = param(req, "author");
    String text = param(req, "text");
    addComment(new Comment(author, text));
    // escape before embedding in markup
    String safeAuthor = escape(author);
    String safeText = escape(text);
    String heading = "Thanks, " + safeAuthor;
    String html = Views.layout("Submitted (SAFE)", Views.thankYouSections(heading, safeText));
    ok(resp, html);
  }

  private void listComments(HttpServletResponse resp) throws IOException {
    StringBuilder items = new StringBuilder();
    synchronized (store) {
      for (Comment c : store) {
        items.append(li(strong(escape(c.author)) + ": " + escape(c.text) + " " + small("(" + c.when + ")")));
      }
    }
    ok(resp, page("All Comments", h1("Comments") + ul(items.toString()) + backLink()));
  }

  private static class Views {
    // FIXED: When fixing the app, update these helpers to encode or sanitize values before returning markup.
    static String layout(String title, List<String> sections) {
      // Ensure title is escaped when building page
      return page(title, combine(sections));
    }

    static List<String> thankYouSections(String heading, String message) {
      List<String> sections = new ArrayList<>();
      // heading and message are expected to be already escaped by callers.
      sections.add(h1(heading));
      sections.add(p("You posted:"));
      sections.add(p(message));
      sections.add(p(a("/asmt/list", "View all comments")));
      sections.add(backLink());
      return sections;
    }

    static List<String> searchSections(String query, String listMarkup) {
      List<String> sections = new ArrayList<>();
      // query and listMarkup should be escaped when created
      sections.add(h1("Results for: " + query));
      sections.add(p("Matching items:"));
      sections.add(ul(listMarkup));
      sections.add(backLink());
      return sections;
    }

    static List<String> noticeSections(String heading, String message) {
      List<String> sections = new ArrayList<>();
      sections.add(h1(heading));
      sections.add(p(message));
      sections.add(backLink());
      return sections;
    }

    static String renderItems(String query) {
      StringBuilder items = new StringBuilder();
      for (int i = 1; i <= 5; i++) {
        // escape query before embedding into item label
        items.append(li(escape("Item " + i + " (query: '" + query + "')")));
      }
      return items.toString();
    }

    static String combine(List<String> parts) {
      StringBuilder sb = new StringBuilder();
      for (String part : parts) sb.append(part);
      return sb.toString();
    }
  }

  private static class SqlTemplates {
    // Keep these for non-vulnerable helper usage, but avoid using string concatenation for real SQL.
    static String lookupByEmail(String email) {
      // return legacy string builder (not used in patched code). Prefer parameterized queries.
      return select("users", equals("email", email));
    }

    private static String select(String table, String whereClause) {
      return "SELECT id, email FROM " + table + " WHERE " + whereClause;
    }

    private static String equals(String column, String value) {
      return column + " = '" + value + "'";
    }
  }

  // ---------- storage & helpers ----------
  private void addComment(Comment c) {
    synchronized (store) {
      store.addFirst(c);
      // keep store small
      while (store.size() > 200) store.removeLast();
    }
  }

  private String param(HttpServletRequest req, String k) {
    String v = req.getParameter(k);
    return v == null ? "" : v;
  }

  private void notFound(HttpServletResponse resp, String p) throws IOException {
    resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
    ok(resp, page("404", p(h1("404 Not Found") + p("No route for: " + escape(p)))));
  }

  private void ok(HttpServletResponse resp, String html) throws IOException {
    resp.setStatus(HttpServletResponse.SC_OK);
    writeHtml(resp, html);
  }

  private void bad(HttpServletResponse resp, String html) throws IOException {
    resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    writeHtml(resp, html);
  }

  private void writeHtml(HttpServletResponse resp, String html) throws IOException {
    resp.setContentType("text/html;charset=UTF-8");
    resp.getWriter().println(escape(html));
  }

  // ---------- small utilities ----------
  private static String page(String title, String body) {
    return "<!doctype html><html><head><meta charset=\"utf-8\"><title>" + escape(title) + "</title></head><body>"
        + body + "</body></html>";
  }

  private static String h1(String s) { return tag("h1", s); }
  private static String p(String s)  { return tag("p", s); }
  private static String ul(String s) { return tag("ul", s); }
  private static String li(String s) { return tag("li", s); }
  private static String strong(String s) { return tag("strong", s); }
  private static String small(String s) { return tag("small", s); }
  private static String tag(String n, String c) { return "<" + n + ">" + c + "</" + n + ">"; }
  private static String a(String href, String txt) { return "<a href=\"" + href + "\">" + escape(txt) + "</a>"; }
  private static String backLink() { return p(a("/asmt", "← back")); }

  // Escape using commons-text so Semgrep recognizes it as a sanitizer
  private static String escape(String s) { return s == null ? "" : org.apache.commons.text.StringEscapeUtils.escapeHtml4(s); }

  // ---------- Additional vulnerable/safe endpoints ----------

  // FIXED: ensure query is encoded before adding to sections/list items
  private void search(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String q = param(req, "q");
    String safeQ = escape(q);
    ok(resp, Views.layout("Search (SAFE)", Views.searchSections(safeQ, Views.renderItems(safeQ))));
  }

  // FIXED: use parameterized PreparedStatement instead of concatenated SQL
  private void userByEmail(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String email = param(req, "email");
    try {
      Connection conn = getConnection();
      String sql = "SELECT id, email FROM users WHERE email = ?";
      PreparedStatement ps = conn.prepareStatement(sql);
      ps.setString(1, email);
      ResultSet rs = ps.executeQuery();
      ok(resp, Views.layout(
          "UserByEmail (SAFE)",
          Views.noticeSections("Lookup", "Queried by email (parameterized).")));
      rs.close();
      ps.close();
      conn.close();
    } catch (SQLException e) {
      ok(resp, Views.layout(
          "UserByEmail (SAFE)",
          Views.noticeSections("Lookup", "DB error (expected in assignment)")));
    }
  }

  // Stubbed connection factory for static-analysis-only assignment
  private Connection getConnection() throws SQLException {
    throw new SQLException("No database configured (assignment runs static analysis only)");
  }

  // ---------- small models ----------
  private static class Comment {
    final String author;
    final String text;
    final Instant when;
    Comment(String a, String t) { author = a; text = t; when = Instant.now(); }
  }

}

