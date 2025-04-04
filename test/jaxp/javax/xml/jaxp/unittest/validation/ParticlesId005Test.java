/*
 * Copyright (c) 2014, 2024, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package validation;

import java.io.File;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/*
 * @test
 * @library /javax/xml/jaxp/libs /javax/xml/jaxp/unittest
 * @run testng/othervm validation.ParticlesId005Test
 * @summary Test Schema Validator can parse multiple or unbounded occurs.
 */
public class ParticlesId005Test {

    boolean errorFound;

    DocumentBuilder documentBuilder;

    private void printMethodName() {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        System.out.println(stack[2].getMethodName());
    }

    public ParticlesId005Test() throws Exception {
        SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Schema schema = factory.newSchema(new File(getClass().getResource("particlesId005.xsd").getFile()));

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setSchema(schema);

        documentBuilder = dbf.newDocumentBuilder();
        documentBuilder.setErrorHandler(new ErrorHandler() {
            public void error(SAXParseException e) throws SAXException {
                System.out.println("Error: " + e.getMessage());
                errorFound = true;
            }

            public void fatalError(SAXParseException e) throws SAXException {
                System.out.println("Fatal error: " + e.getMessage());
            }

            public void warning(SAXParseException e) throws SAXException {
                System.out.println("Warning: " + e.getMessage());
            }
        });
    }

    @Test
    public void testNoOptimizationWithChoice() throws Exception {
        printMethodName();

        File xmlFile = new File(getClass().getResource("particlesId005.xml").getFile());
        try {
            errorFound = false;
            documentBuilder.parse(xmlFile);
        } catch (SAXException ex) {
            Assert.fail(ex.getMessage());
        }
        if (errorFound) {
            Assert.fail("Unexpected validation error reported");
        }
    }

}
