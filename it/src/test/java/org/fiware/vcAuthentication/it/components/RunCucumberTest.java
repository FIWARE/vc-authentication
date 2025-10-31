package org.fiware.vcAuthentication.it.components;

import org.junit.platform.suite.api.ConfigurationParameter;
import org.junit.platform.suite.api.IncludeEngines;
import org.junit.platform.suite.api.SelectClasspathResource;
import org.junit.platform.suite.api.Suite;

import static io.cucumber.junit.platform.engine.Constants.PLUGIN_PROPERTY_NAME;

/**
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 * @author <a href="https://github.com/vramperez">Victor Ramperez</a>
 */
@Suite
@IncludeEngines("cucumber")
@SelectClasspathResource("it")
@ConfigurationParameter(key = PLUGIN_PROPERTY_NAME, value = "pretty")
public class RunCucumberTest {
}