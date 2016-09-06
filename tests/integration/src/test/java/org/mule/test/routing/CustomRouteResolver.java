/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.test.routing;

import org.mule.runtime.api.metadata.DataType;
import org.mule.runtime.core.api.DefaultMuleException;
import org.mule.runtime.core.api.MuleContext;
import org.mule.runtime.core.api.MuleEvent;
import org.mule.runtime.core.api.MuleException;
import org.mule.runtime.core.api.MuleMessage;
import org.mule.runtime.core.api.context.MuleContextAware;
import org.mule.runtime.core.api.processor.MessageProcessor;
import org.mule.runtime.core.config.i18n.CoreMessages;
import org.mule.runtime.core.routing.DynamicRouteResolver;

import java.util.ArrayList;
import java.util.List;

public class CustomRouteResolver implements DynamicRouteResolver {

  static List<MessageProcessor> routes = new ArrayList<>();

  @Override
  public List<MessageProcessor> resolveRoutes(MuleEvent event) {
    return routes;
  }

  public static class AddLetterMessageProcessor implements MessageProcessor {

    private String letter;

    public AddLetterMessageProcessor(String letter) {
      this.letter = letter;
    }

    @Override
    public MuleEvent process(MuleEvent event) throws MuleException {
      try {
        return MuleEvent.builder(event).message(MuleMessage.builder(event.getMessage()).payload(letter).build()).build();
      } catch (Exception e) {
        throw new DefaultMuleException(e);
      }
    }

  }

  public static class FailingMessageProcessor implements MessageProcessor {

    @Override
    public MuleEvent process(MuleEvent event) throws MuleException {
      throw new DefaultMuleException(CoreMessages.createStaticMessage(""));
    }
  }

  public static class AddLetterThenFailsMessageProcessor implements MessageProcessor, MuleContextAware {

    private String letter;
    private MuleContext muleContext;

    public AddLetterThenFailsMessageProcessor(String letter) {
      this.letter = letter;
    }

    @Override
    public MuleEvent process(MuleEvent event) throws MuleException {
      try {
        event = MuleEvent
            .builder(event).message(
                                    MuleMessage.builder(event.getMessage())
                                        .payload(muleContext.getTransformationService()
                                            .transform(event.getMessage(), DataType.STRING).getPayload() + letter)
                                        .build())
            .build();
      } catch (Exception e) {
      }
      throw new DefaultMuleException(CoreMessages.createStaticMessage(""));
    }

    @Override
    public void setMuleContext(MuleContext context) {
      this.muleContext = context;
    }
  }
}
