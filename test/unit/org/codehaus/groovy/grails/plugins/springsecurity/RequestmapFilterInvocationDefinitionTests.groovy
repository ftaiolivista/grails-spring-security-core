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

import grails.test.GrailsUnitTestCase

import org.codehaus.groovy.grails.commons.ConfigurationHolder as CH
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.vote.AuthenticatedVoter
import org.springframework.security.access.vote.RoleVoter
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler
import org.springframework.security.web.util.AntPathRequestMatcher
import org.springframework.security.access.SecurityConfig

/**
 * Unit tests for RequestmapFilterInvocationDefinition.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class RequestmapFilterInvocationDefinitionTests extends GrailsUnitTestCase {

	private RequestmapFilterInvocationDefinition _fid = new RequestmapFilterInvocationDefinition()
	private final FakeApplication _application = new FakeApplication()

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
//		_application.addToLoaded(TestRequestmap)
		ReflectionUtils.application = _application
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		ReflectionUtils.application = null
		SpringSecurityUtils.resetSecurityConfig()
		CH.config = null
	}

	void testSplit() {
		assertEquals(['ROLE_1', 'ROLE_2', 'ROLE_3', 'ROLE_4', 'ROLE_5'], _fid.split('ROLE_1, ROLE_2,,,ROLE_3 ,ROLE_4,ROLE_5'))
		assertEquals(['hasAnyRole("ROLE_1","ROLE_2")'], _fid.split('hasAnyRole("ROLE_1","ROLE_2")'))
	}

	void testStoreMapping() {

		assertEquals 0, _fid.configAttributeMap.size()

		_fid.storeMapping new AntPathRequestMatcher('/foo/bar'), [new SecurityConfig('ROLE_ADMIN')]
		assertEquals 1, _fid.configAttributeMap.size()

		_fid.storeMapping new AntPathRequestMatcher('/foo/bar'), [new SecurityConfig('ROLE_USER')]
		assertEquals 1, _fid.configAttributeMap.size()

		_fid.storeMapping new AntPathRequestMatcher('/other/path'), [new SecurityConfig('ROLE_SUPERUSER')]
		assertEquals 2, _fid.configAttributeMap.size()
	}

	void testReset() {
		_fid = new TestRequestmapFilterInvocationDefinition()
		_fid.roleVoter = new RoleVoter()
		_fid.authenticatedVoter = new AuthenticatedVoter()
		_fid.expressionHandler = new DefaultWebSecurityExpressionHandler()

		assertEquals 0, _fid.configAttributeMap.size()

		_fid.reset()

		assertEquals 2, _fid.configAttributeMap.size()
	}

	void testInitialize() {
		_fid = new TestRequestmapFilterInvocationDefinition()
		_fid.roleVoter = new RoleVoter()
		_fid.authenticatedVoter = new AuthenticatedVoter()
		_fid.expressionHandler = new DefaultWebSecurityExpressionHandler()

		assertEquals 0, _fid.configAttributeMap.size()

		_fid.initialize()
		assertEquals 2, _fid.configAttributeMap.size()

		_fid.resetConfigs()

		_fid.initialize()
		assertEquals 0, _fid.configAttributeMap.size()
	}

	void testDetermineUrl() {

		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def chain = new MockFilterChain()
		request.contextPath = '/context'

		request.servletPath = '/context/foo'
		assertEquals '/foo', _fid.determineUrl(new FilterInvocation(request, response, chain))

		request.servletPath = '/context/fOo/Bar?x=1&y=2'
		assertEquals '/fOo/Bar?x=1&y=2', _fid.determineUrl(new FilterInvocation(request, response, chain))
	}

	void testSupports() {
		assertTrue _fid.supports(FilterInvocation)
	}
}

class TestRequestmapFilterInvocationDefinition extends RequestmapFilterInvocationDefinition {
	protected Map<String, String> loadRequestmaps() {
		['/foo/bar': 'ROLE_USER', '/admin/**': 'ROLE_ADMIN']
	}
}
