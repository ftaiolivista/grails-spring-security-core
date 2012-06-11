/* Copyright 2006-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.codehaus.groovy.grails.plugins.springsecurity

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.authentication.RememberMeAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder as SCH
import org.springframework.security.web.PortResolverImpl
import org.springframework.security.web.savedrequest.DefaultSavedRequest
import org.codehaus.groovy.grails.commons.DefaultGrailsApplication
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.web.context.WebApplicationContext
import javax.servlet.ServletContext
import org.springframework.mock.web.MockServletContext
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.commons.GrailsApplication

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AjaxAwareAccessDeniedHandlerTests extends GroovyTestCase {

	private final _handler = new AjaxAwareAccessDeniedHandler()
	private final _application = new FakeApplication()

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		
		ServletContext servletContext = new MockServletContext()
		def app = new DefaultGrailsApplication()
		def requestCache = new HttpSessionRequestCache(createSessionAllowed: true)
		def beans = [(GrailsApplication.APPLICATION_ID): app, 'requestCache': requestCache]
		def ctx = [getBean: { String name, Class<?> c = null -> beans[name] },
				   containsBean: { String name -> beans.containsKey(name) } ] as WebApplicationContext
		servletContext.setAttribute WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, ctx
		app.mainContext = ctx
		SpringSecurityUtils.application = app
		
		_handler.errorPage = '/fail'
		_handler.ajaxErrorPage = '/ajaxFail'
		_handler.portResolver = new PortResolverImpl()
		_handler.authenticationTrustResolver = new AuthenticationTrustResolverImpl()
		ReflectionUtils.application = _application
		ReflectionUtils.setConfigProperty 'ajaxHeader', SpringSecurityUtils.AJAX_HEADER
	}

// TODO: check requestCache
//	void testHandleAuthenticatedRememberMe() {
//		def request = new MockHttpServletRequest()
//		def response = new MockHttpServletResponse()
//
//		SCH.context.authentication = new RememberMeAuthenticationToken('username', 'password', null)
//
//		assertNull request.session.getAttribute(DefaultSavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY)
//		_handler.handle request, response, new AccessDeniedException('fail')
//		assertNotNull request.session.getAttribute(DefaultSavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY)
//
//		assertEquals 'http://localhost/fail', response.redirectedUrl
//	}

	void testHandleAuthenticatedAjax() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()

		request.addHeader SpringSecurityUtils.AJAX_HEADER, 'XHR'

		_handler.handle request, response, new AccessDeniedException('fail')

		assertEquals 'http://localhost/ajaxFail', response.redirectedUrl
	}

	void testHandleAuthenticatedNotAjax() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()

		_handler.handle request, response, new AccessDeniedException('fail')

		assertEquals 'http://localhost/fail', response.redirectedUrl
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SCH.context.authentication = null
		ReflectionUtils.application = null
	}
}
