
package com.ajmusgrove.filters;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.*;

import java.security.SecureRandom;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.regex.PatternSyntaxException;

import java.lang.reflect.Type;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.InstanceCreator;
import com.google.gson.reflect.TypeToken;
import com.google.gson.annotations.SerializedName;

import com.ajmusgrove.util.*;

/**
 * SecHeaders J2EE/Filter Plugin. For complete information see the documentation.
 * @author <a href="https://www.ajmusgrove.com">Arthur J Musgrove</a>
 * @version 1.0
 * @see <a href="https://www.ajmusgrove.com/secheaders.html">SecHeaders Documentation</a>
 */
public class SecHeaders implements Filter
{
	static final private int NONCE_LENGTH = 24;
	static final public String DEFAULT_LOGGER_NAME =
		"com.ajmusgrove.filters.SecHeaders";
	static final public String DEFAULT_CONFIG_FILE =
		"/WEB-INF/secheaders.json";

	/**
	 * If a NOnce is used in the Content-Security-Policy, it will
	 * be stored in a Request Attribute with this name. It is also
	 * accessible using the static getNOnce() function in this
	 * class.
	 */
	static final public String STORED_NONCE="_SecHeadersCSPNOnce";

	static final public String LOGGER_NAME_PARAM="logger-key";
	static final public String CONFIG_FILE_PARAM="config-file";
	static final public String LOGGING_LEVEL_PARAM="logging-level";

	static final private String NONCE_STRING="#####NONCE#####";
	static public final int DEFAULT_NONCE_LENGTH=20;

	static final private String BANNER_HEADER="X-SecHeaders";
	static final private String BANNER_TEXT=
		"SecHeaders Plugin from https://www.ajmusgrove.com/secheaders.html";

	static final private int DEFAULT_WHITELIST_FAIL_ERROR = 404;

	private class Config
	{
		public String getCORSFile() { return m_cors_file; }

		@SerializedName("cors")
		private String m_cors_file;

		@SerializedName("nonce-length")
		private int m_nonce_length;

		@SerializedName("whitelistFailError")
		private int m_whitelist_fail_error;

		@SerializedName("rules")
		Rule[] m_rules;

		@SerializedName("proxyprotoheader")
		private String m_proxyprotoheader;

		void postLoadProcessing()
			throws IOException, ServletException, PatternSyntaxException
		{
			if (m_nonce_length <= 0)
				m_nonce_length = DEFAULT_NONCE_LENGTH;

			if (m_whitelist_fail_error < 400 || m_whitelist_fail_error > 600)
				m_whitelist_fail_error = DEFAULT_WHITELIST_FAIL_ERROR;

			if (m_rules != null)
			{
				for (Rule r : m_rules)
					r.postLoadProcessing(this);
			}
			else
			{
				m_rules = new Rule[0];
			}

			logConfigInfo();
		}

		void logConfigInfo()
		{
			m_logger.config("NOnce length is " + m_nonce_length);
			m_logger.config("Loaded " + m_rules.length + " rules");
			if (m_cors_file != null)
				m_logger.config("CORS file was " + m_cors_file);
			else
				m_logger.config("No CORS configuration file");
			if (m_proxyprotoheader != null)
				m_logger.config("Proxy Protocol Header " + m_proxyprotoheader);
			else
				m_logger.config("No Proxy Protocol Header");
		}
	}

	class Rule
	{
		private String comment;

		transient Pattern[] m_match_patterns;

		@SerializedName("url-patterns")
		private String[] m_url_matches;
		transient Pattern[] m_url_patterns;

		@SerializedName("url-excludes")
		private String[] m_url_excludes;
		transient Pattern[] m_url_excludes_patterns;

		@SerializedName("host-patterns")
		String[] m_host_matches;
		transient Pattern[] m_host_patterns;

		@SerializedName("whitelist")
		String[] m_whitelist;
		transient Pattern[] m_whitelist_patterns;

		@SerializedName("forcehttps")
		private boolean m_forcehttps;

		@SerializedName("csp")
		private Map<String,Object> m_csp;

		@SerializedName("headers")
		Map<String,Object> m_headers;

		@SerializedName("cors")
		private String m_cors_filename;

		@SerializedName("name")
		private String m_name;

		transient String[] m_csp_sha;

		boolean ruleApplies(HttpServletRequest hsr)
		{
			if (m_url_patterns != null)
			{
				String uri = hsr.getRequestURI();
				String cp = hsr.getContextPath();
				String lp = uri.substring(cp.length(),uri.length());

				if (!anyMatch(lp,m_url_patterns))
					return false;

				if (m_url_excludes_patterns != null &&
					anyMatch(lp,m_url_excludes_patterns))
					return false;
			}

			if (m_host_patterns != null)
				if (! anyMatch(hsr.getServerName(),m_host_patterns))
					return false;

			return true;
		}

		void applyRule(HttpServletRequest hsreq,
			HttpServletResponse hsres, CSPBuildup csp, PolicyToApply pa)
			throws IOException
		{
			if (!ruleApplies(hsreq))
			{
				return;
			}

			m_logger.fine("rule matches, applying " +
				m_headers.size());
			
			if (m_whitelist_patterns != null)
			{
				String uri = hsreq.getRequestURI();
				String cp = hsreq.getContextPath();
				String lp = uri.substring(cp.length(),uri.length());

				m_logger.fine(String.format("checking '%s' in rule '%s' " +
					"against %d patterns",
					lp,m_name,m_whitelist_patterns.length));
				if (!anyMatch(lp,m_whitelist_patterns))
				{
					m_logger.warning(String.format("'%s' failed whitelist " +
						"rule in '%s",lp,m_name));
					pa.m_send_error = m_config.m_whitelist_fail_error;
					pa.m_send_error_detail = hsreq.getRequestURI().toString();
					return;
				}
			}

			if (m_forcehttps)
				doForceHttps(hsreq,hsres, pa);

			if (m_headers != null)
				for (String key : m_headers.keySet())
					if (m_headers.get(key) != null)
						pa.m_headers.put(key, m_headers.get(key).toString());
					else
						pa.m_headers.remove(key);
				
			if (m_csp != null)
				csp.processCSP(m_csp, m_csp_sha);
		}

		void postLoadProcessing(Config c)
			throws IOException, ServletException, PatternSyntaxException
		{
			m_url_patterns = compileGlobs(m_url_matches);
			m_url_excludes_patterns = compileGlobs(m_url_excludes);
			m_host_patterns = compileGlobs(m_host_matches);
			m_whitelist_patterns = compileGlobs(m_whitelist);

			if (m_csp != null && m_csp.get("script-sha-file") != null)
			{
				m_csp_sha = loadFileLinesAsArray(
					m_csp.get("script-sha-file").toString());
				// fixup
				if (m_csp_sha != null)
					for (int i = 0; i < m_csp_sha.length; i++)
						m_csp_sha[i] = String.format("'%s'",m_csp_sha[i]);
			}

			if (m_headers == null) m_headers = new HashMap<String,Object>();
			m_config = c;
		}

		void doForceHttps(HttpServletRequest hsreq,
			HttpServletResponse hsres, PolicyToApply pa)
			throws IOException
		{
			String p = hsreq.getScheme();
			if (p.equalsIgnoreCase("http"))
			{
				if (! (m_config.m_proxyprotoheader != null &&
				  hsreq.getHeader(m_config.m_proxyprotoheader) != null &&
				  hsreq.getHeader(m_config.m_proxyprotoheader).equals("https")))
				{
					String url = hsreq.getRequestURL().toString();
					String qs = hsreq.getQueryString();
					StringBuffer sb = new StringBuffer();
					sb.append("https");
					sb.append(url.substring(4,url.length()));
					if (qs != null)
					{
						sb.append('?');
						sb.append(qs);
					}

					m_logger.fine("Redirecting to " + sb.toString());
					pa.m_send_redirect = sb.toString();
				}
			}
		}

		Config m_config;
	}

	private class CORSRule
	{
	}

	static Set<String> ms_csp_sections;
	static {
		ms_csp_sections = new LinkedHashSet<String>();
		ms_csp_sections.add("default-src");
		ms_csp_sections.add("script-src");
		ms_csp_sections.add("style-src");
		ms_csp_sections.add("frame-src");
		ms_csp_sections.add("img-src");
		ms_csp_sections.add("connect-src");
		ms_csp_sections.add("font-src");
		ms_csp_sections.add("frame-src");
		ms_csp_sections.add("manifest-src");
		ms_csp_sections.add("media-src");
		ms_csp_sections.add("object-src");
		ms_csp_sections.add("child-src");
		ms_csp_sections.add("worker-src");
		ms_csp_sections.add("base-uri");
		ms_csp_sections.add("form-action");
		ms_csp_sections.add("frame-ancestors");
		ms_csp_sections.add("plugin-types");
		ms_csp_sections.add("require-sri-for");
		ms_csp_sections.add("report-uri");
		ms_csp_sections.add("sandbox");
	}

	private static final String[] NONCE_STRING_ARRAY =
		new String[] { NONCE_STRING };
	private class CSPBuildup
	{
		String getCSPHeader()
		{
			if (m_style_nonce)
				addSection("style-src",NONCE_STRING_ARRAY);
			if (m_script_nonce)
				addSection("script-src",NONCE_STRING_ARRAY);

			if (m_csp == null || m_csp.size() == 0)
				return null;

			StringBuffer ret = new StringBuffer();

			for (String key : m_csp.keySet())
			{
				if (ret.length() > 0)
					ret.append(' ');
				ret.append(key);
				for (String val : m_csp.get(key))
				{
					ret.append(' ');
					ret.append(val);
				}
				ret.append(';');
			}

			if (m_block_all_mixed_content)
			{
				if (ret.length() > 0)
					ret.append(' ');
				ret.append("block-all-mixed-content;");
			}

			if (m_upgrade_insecure_requests)
			{
				if (ret.length() > 0)
					ret.append(' ');
				ret.append("block-all-mixed-content;");
			}

			return ret.toString();
		}

		CSPBuildup()
		{
			m_csp = new LinkedHashMap<String,Set<String>>();
		}

		void processCSP(Map<String,Object> csp, String[] csp_sha)
		{
			for (String key : csp.keySet())
			{
				Object val = csp.get(key);
				if (ms_csp_sections.contains(key))
				{
					String[] entries = val.toString().split(" ");
					addSection(key,entries);
				}
				else if (key.equals("script-sha-file") && csp_sha != null)
				{
					addSection("script-src",csp_sha);
				}
				else if (key.equals("block-all-mixed-content"))
				{
					if (! (val instanceof Boolean))
						m_logger.warning(
							"CSP value for " + key + " not boolean");
					else
						m_block_all_mixed_content = (Boolean)val;
				}
				else if (key.equals("upgrade-insecure-requests"))
				{
					if (! (val instanceof Boolean))
						m_logger.warning(
							"CSP value for " + key + " not boolean");
					else
						m_block_all_mixed_content = (Boolean)val;
				}
				else if (key.equals("script-nonce"))
				{
					if (! (val instanceof Boolean))
						m_logger.warning(
							"CSP value for " + key + " not boolean");
					else
						m_script_nonce = (Boolean)val;
				}
				else if (key.equals("style-nonce"))
				{
					if (! (val instanceof Boolean))
						m_logger.warning(
							"CSP value for " + key + " not boolean");
					else
						m_style_nonce = (Boolean)val;
				}
				else
				{
					m_logger.warning("Unknown CSP specification " + key);
				}
			}
		}

		void addSection(String section, String[] entries)
		{
			Set<String> r = m_csp.get(section);

			if (r == null)
			{
				r = new LinkedHashSet<String>();
				m_csp.put(section,r);
			}

			for (String s : entries)
				r.add(s);
		}

		Map<String,Set<String>> m_csp;
		String m_nonce;
		boolean m_block_all_mixed_content;
		boolean m_script_nonce;
		boolean m_style_nonce;
		boolean m_upgrade_insecure_requests;
	}

	String[] loadFileLinesAsArray(String filename)
		throws IOException
	{
		InputStream is = m_filter_config.getServletContext()
			.getResourceAsStream(filename);
		if (is == null)
		{
			m_logger.severe("could not find SHA file resource " + filename);
			return null;
		}

		try
		{
			BufferedReader bfr = new BufferedReader(
				new InputStreamReader(is));
			ArrayList<String> al = new ArrayList<String>();
			String s;
			while ((s = bfr.readLine()) != null)
				al.add(s);
			return al.toArray(new String[0]);
		}
		finally
		{
			try
			{
				if (is != null) is.close();
			}
			catch (IOException ex)
			{
				m_logger.severe(ex.toString());
			}
		}
	}

	static Pattern[] compileGlobs(String[] globs)
		throws PatternSyntaxException
	{
		if (globs == null) return null;

		Pattern[] ret = new Pattern[globs.length];

		for (int i = 0; i < globs.length; i++)
			ret[i] = Pattern.compile(GlobMatcher.convertGlobToRegex(
				globs[i]));

		return ret;
	}

	static class AnyMatchResult
	{
		AnyMatchResult(String input, Pattern[] patterns)
		{
			m_input = input;
			m_patterns = patterns;
			m_hash_code = m_input.hashCode() ^ patterns.hashCode();
		}

		@Override
		public int hashCode()
		{
			return m_hash_code;
		}

		@Override
		public boolean equals(Object o)
		{
			if (! (o instanceof AnyMatchResult))
				return false;

			AnyMatchResult amr = (AnyMatchResult)o;

			return amr.m_input.equals(m_input) &&
				amr.m_patterns == m_patterns;
		}

		String m_input;
		Pattern[] m_patterns;
		int m_hash_code;
	}
	
	static WeakHashMap<AnyMatchResult,Boolean> m_any_match_results =
		new WeakHashMap<AnyMatchResult,Boolean>();

	static boolean anyMatch(String input, Pattern[] patterns)
	{
		AnyMatchResult amr = new AnyMatchResult(input,patterns);
		Boolean res;

		synchronized (m_any_match_results)
		{
			res = m_any_match_results.get(amr);
		}

		if (res != null)
			return res;

		for (Pattern p : patterns)
		{
			Matcher m = p.matcher(input);
			if (m.matches())
			{
				res = true;
				break;
			}
		}

		if (res == null) res = false;

		synchronized (m_any_match_results)
		{
			m_any_match_results.put(amr,res);
		}

		return res;
	}

	private static final ThreadLocal<String> m_nonce =
		new ThreadLocal<String>()
		{
			@Override
			protected String initialValue() 
			{
				return generateNOnce();
			}

			@Override
			public String get()
			{
				String ret = super.get();
				if (ret == null)
				{
					ret = generateNOnce();
					set(ret);
				}
				return ret;
			}
		};

	static private String generateNOnce()
	{
		byte ret[] = new byte[m_nonce_length];
		m_sr.nextBytes(ret);
		return m_encoder.encodeToString(ret);
	}

	/**
	 * Returns the generated nonce for this particular invocation. This
	 * will change on each time the page is reloaded, but will remain
	 * constant throughout a single page request. This value
	 * is what is in the Content-Security-Policy header if enabled
	 * and can be included in the script tags if strict-dynamic mode
	 * is enabled. The NOnce length default is 24 bytes (which are
	 * then Base64 encoded) but can be changed in the configuration
	 * as described in the documentation.
	 *
	 * @since 1.0
	 * @return NOnce String for this invocation.
	 */
	static public String getNOnce()
	{
		return m_nonce.get();
	}

	/**
	 * Filter startup. Loads configuration file.
	 */
	@Override
	public void init(FilterConfig filterConfig)
		throws ServletException
	{
		m_filter_config = filterConfig;

		m_logger_name = filterConfig.getInitParameter(LOGGER_NAME_PARAM);
		if (m_logger_name == null)
			m_logger_name = DEFAULT_LOGGER_NAME;
		m_config_file = filterConfig.getInitParameter(CONFIG_FILE_PARAM);
		if (m_config_file == null)
			m_config_file = DEFAULT_CONFIG_FILE;
		m_logging_level = filterConfig.getInitParameter(LOGGING_LEVEL_PARAM);

		m_logger = Logger.getLogger(m_logger_name);

		if (m_logging_level != null)
		{
			try
			{
				m_logger.setLevel(Level.parse(m_logging_level));
			}
			catch (IllegalArgumentException ex)
			{
				m_logger.severe(ex.toString());
			}
		}

		try
		{
			InputStream is = m_filter_config.getServletContext()
				.getResourceAsStream(m_config_file);
			loadConfiguration(is);
			m_nonce_length = m_config.m_nonce_length;
		}
		catch (PatternSyntaxException ex)
		{
			m_logger.severe(ex.toString());
			throw new ServletException(ex);
		}
		catch (IOException ex)
		{
			m_logger.severe(ex.toString());
			throw new ServletException(ex);
		}

		m_logger.info("SecHeaders Initialized and Ready");
	}

	class PolicyToApply
	{
		String m_local_path;
		int m_send_error;
		String m_send_error_detail;
		String m_send_redirect;
		Map<String,String> m_headers;
		String m_csp_header;

		PolicyToApply()
		{
			m_headers = new LinkedHashMap<String,String>();
		}
	}

	/**
	 * Filter on each request. This does the processing in this order.
	 * For complete information on how this operates, see the complete
	 * developer documentation.
	 *
	 * @param request The incoming servlet request
	 * @param response Response where the headers will be added
	 * @param chain Filter chain to continue filter invocation
	 *
	 * @throws ClassCastException If ServletRequest or ServletResponse cannot be cast to their javax.servlet.http counterparts
	 *
	 * @since 1.0
	 * @see <a href="https://www.ajmusgrove.com/secheaders.html">SecHeaders Documentation</a>
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
		FilterChain chain)
		throws IOException, ServletException
	{
		m_nonce.set(null); // wipe out any existing nonce

		HttpServletRequest hsreq = (HttpServletRequest)request;
		HttpServletResponse hsres = (HttpServletResponse)response;

		hsres.setHeader(BANNER_HEADER,BANNER_TEXT);

		String uri = hsreq.getRequestURI();
		String cp = hsreq.getContextPath();
		String lp = uri.substring(cp.length(),uri.length());

		PolicyToApply pa;
		synchronized (m_policy_cache)
		{
			pa = m_policy_cache.get(lp);
		}
		if (pa != null)
		{
			if (applyPolicy(hsreq,hsres,pa))
				chain.doFilter(request,response);
			return;
		}

		try
		{
			pa = new PolicyToApply();
			CSPBuildup csp = new CSPBuildup();
			pa.m_local_path = lp;

			for (Rule r : m_config.m_rules)
				r.applyRule(hsreq,hsres,csp,pa);
			pa.m_csp_header = csp.getCSPHeader();

			synchronized (m_policy_cache)
			{
				m_policy_cache.put(lp,pa);
			}

			if (applyPolicy(hsreq,hsres,pa))
				chain.doFilter(request,response);
		}
		catch (RuntimeException ex)
		{
			ex.printStackTrace();
			m_logger.severe(ex.toString());
		}
	}

	// return if filter chain processing should continue
	private boolean applyPolicy(HttpServletRequest hsreq,
		HttpServletResponse hsres, PolicyToApply pa)
		throws IOException, ServletException
	{
		if (pa.m_send_redirect != null)
		{
			hsres.sendRedirect(pa.m_send_redirect);
			return false;
		}
		else if (pa.m_send_error >= 300)
		{
			hsres.sendError(pa.m_send_error,pa.m_send_error_detail);
			return false;
		}
		else
		{
			if (pa.m_headers != null)
			{
				for (String key : pa.m_headers.keySet())
				{
					hsres.setHeader(key,pa.m_headers.get(key));
				}
			}

			if (pa.m_csp_header != null)
			{
				String cspHeader = pa.m_csp_header;
				if (cspHeader.indexOf(NONCE_STRING) >= 0)
				{
					String n = String.format("'nonce-%s'",
						m_nonce.get());
					cspHeader = cspHeader.replaceAll(NONCE_STRING,n);
				}
				hsres.setHeader("Content-Security-Policy",cspHeader);
				hsreq.setAttribute(STORED_NONCE,m_nonce.get());
			}

			return true;
		}
	}

	private void loadConfiguration(InputStream is)
		throws IOException, ServletException, PatternSyntaxException
	{
		if (is == null)
		{
			String e = "Failed to locate configuration file " + m_config_file;
			m_logger.severe(e);
			throw new ServletException(e);
		}

		try
		{
			InputStreamReader isr = new InputStreamReader(is);

			m_config = m_gson.fromJson(isr,m_config_token);
			m_config.postLoadProcessing();
		}
		catch (IOException ex)
		{
			ex.printStackTrace();
			m_logger.severe(ex.toString());
			throw ex;
		}
		catch (ServletException ex)
		{
			ex.printStackTrace();
			m_logger.severe(ex.toString());
			throw ex;
		}
		catch (RuntimeException ex)
		{
			ex.printStackTrace();
			m_logger.severe(ex.toString());
			throw ex;
		}
		catch (Throwable ex)
		{
			ex.printStackTrace();
			m_logger.severe(ex.toString());
		}
		finally
		{
			if (is != null)
			{
				try
				{
					is.close();
				}
				catch (IOException ex)
				{
					throw new ServletException(ex);
				}
			}
		}
	}

	public SecHeaders()
	{
		m_config_token =
			new TypeToken<Config>(){}.getType();
		m_gson = new GsonBuilder()
			.registerTypeAdapter(Config.class, new ConfigInstanceCreator())
			.registerTypeAdapter(Rule.class, new RuleInstanceCreator())
			.create();
		m_sr = new SecureRandom();
		m_encoder = Base64.getUrlEncoder().withoutPadding();
		m_policy_cache = new HashMap<String,PolicyToApply>();
	}

	public static void main(String[] args)
	{
		System.out.println("SecHeaders Tests");
		if (args.length != 1)
		{
			System.out.println("Input file name required");
			System.exit(10);
		}

		try
		{
			SecHeaders sh = new SecHeaders();
			sh.m_logger = Logger.getGlobal();
			sh.loadConfiguration(new FileInputStream(args[0]));
			System.out.println("CORSFile is " + sh.m_config.getCORSFile());
		}
		catch (Exception ex)
		{
			ex.printStackTrace();
			System.out.println(ex.toString());
		}
	}

	// have to register InstanceCreators so that inner classes
	// get outer object references
	class ConfigInstanceCreator implements InstanceCreator<Config> {
		public Config createInstance(Type type) {
			return new Config();
		}
	}
	class RuleInstanceCreator implements InstanceCreator<Rule> {
		public Rule createInstance(Type type) {
			return new Rule();
		}
	}

	private FilterConfig m_filter_config;
	private Logger m_logger;
	private Config m_config;
	private java.lang.reflect.Type m_config_token;
	private Gson m_gson;
	private String m_logger_name;
	private String m_config_file;
	private String m_logging_level;
	private Map<String,PolicyToApply> m_policy_cache;
	static private SecureRandom m_sr;
	static private Base64.Encoder m_encoder;
	private static int m_nonce_length;
}
