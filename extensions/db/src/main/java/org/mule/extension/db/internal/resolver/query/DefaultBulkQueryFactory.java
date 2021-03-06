/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.extension.db.internal.resolver.query;

import org.mule.extension.db.internal.parser.QueryTemplateParser;

public class DefaultBulkQueryFactory extends BulkQueryFactory {

  private final String bulkQueryText;

  public DefaultBulkQueryFactory(QueryTemplateParser queryTemplateParser, String bulkQueryText) {
    super(queryTemplateParser);
    this.bulkQueryText = bulkQueryText;
  }

  @Override
  protected String resolveBulkQueries() {
    return bulkQueryText.trim();
  }

  @Override
  public String toString() {
    return bulkQueryText;
  }
}
