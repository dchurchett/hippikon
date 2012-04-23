/** 
 * Part of the Hippikon API, a powerful authoriation
 * security framework for Java applications.
 *
 * Copyright (C) 2005  Dale Churchett
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Contact: Dale Churchett <dale@hippikon.com>
 * Website: http://www.hippikon.com, http://www.hippikon.org
 *
 */
package com.hippikon.security;
 
 /**
  * The Configurable interface forms part of the extensibility mechanism
  * of the authorization framework and should be implemented by fine grained 
  * objects where creating an class simply to define a {@link ProtectedResource} 
  * becomes unwieldy.<p>
  *
  * The need for the Configurable mechanism stemmed from
  * a requirement to provide attribute and screen-section based security in
  * a complex enterprise web application.<p>
  *
  * The {@link #getName()} method should return the type name of 
  * the Configured protected object. This differs from {@link ProtectedResource#name()},
  * which returns the type of ProtectedResource.<p>
  *
  * An example of Configurable objects could be reports generated by a reporting engine
  * (e.g., Crystal Reports) that need to be integrated into a JSP environment.
  * The Report interface that wraps each generated report would implement Configurable and 
  * use the ProtectedResource annotation. The <code>name()</code> annotated attribut 
  * would return "Report" while <code>getName()</code> would return the unique name of a 
  * particular report, which would be used as protected-resource key in the policy-store XML 
  * configuration file.<p>
  *
  * @author Dale Churchett
  * @version $Id: Configurable.java,v 1.2 2012/04/23 14:25:16 dalehippikon Exp $
  * @since JDK 1.2.2
  */
 public interface Configurable {
 
     /**
      * Returns the name of a Configurable object. This 
      * will not be the class name or type of ProtectedResource, 
      * but some other unique identifier that is used by the framework to
      * look up permissions in the PolicyStore..
      *
      * @return a unique identifier of a Configurable object instance
      */
     public abstract String getName();
 
 }
