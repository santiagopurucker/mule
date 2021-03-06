/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.runtime.core.routing;

import org.apache.commons.lang.Validate;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.mule.runtime.core.api.MuleContext;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.core.api.construct.FlowConstruct;
import org.mule.runtime.core.api.construct.FlowConstructAware;
import org.mule.runtime.core.api.context.MuleContextAware;
import org.mule.runtime.api.lifecycle.Disposable;
import org.mule.runtime.api.lifecycle.Initialisable;
import org.mule.runtime.api.lifecycle.InitialisationException;
import org.mule.runtime.api.lifecycle.Lifecycle;
import org.mule.runtime.api.lifecycle.Startable;
import org.mule.runtime.api.lifecycle.Stoppable;
import org.mule.runtime.core.api.processor.Processor;
import org.mule.runtime.core.api.routing.filter.Filter;

/**
 * A holder for a pair of MessageProcessor and Filter.
 */
public class MessageProcessorFilterPair implements FlowConstructAware, MuleContextAware, Lifecycle {

  private final Processor messageProcessor;
  private final Filter filter;

  public MessageProcessorFilterPair(Processor messageProcessor, Filter filter) {
    Validate.notNull(messageProcessor, "messageProcessor can't be null");
    Validate.notNull(filter, "filter can't be null");
    this.messageProcessor = messageProcessor;
    this.filter = filter;
  }

  public Processor getMessageProcessor() {
    return messageProcessor;
  }

  public Filter getFilter() {
    return filter;
  }

  @Override
  public String toString() {
    return ToStringBuilder.reflectionToString(this, ToStringStyle.SHORT_PREFIX_STYLE);
  }

  // This class being just a logic-less tuple, it directly delegates lifecyle
  // events to its members, without any control.

  public void setFlowConstruct(FlowConstruct flowConstruct) {
    if (messageProcessor instanceof FlowConstructAware) {
      ((FlowConstructAware) messageProcessor).setFlowConstruct(flowConstruct);
    }
    if (filter instanceof FlowConstructAware) {
      ((FlowConstructAware) filter).setFlowConstruct(flowConstruct);
    }
  }

  public void setMuleContext(MuleContext context) {
    if (messageProcessor instanceof MuleContextAware) {
      ((MuleContextAware) messageProcessor).setMuleContext(context);
    }
    if (filter instanceof MuleContextAware) {
      ((MuleContextAware) filter).setMuleContext(context);
    }
  }

  public void initialise() throws InitialisationException {
    if (messageProcessor instanceof Initialisable) {
      ((Initialisable) messageProcessor).initialise();
    }
    if (filter instanceof Initialisable) {
      ((Initialisable) filter).initialise();
    }
  }

  public void start() throws MuleException {
    if (messageProcessor instanceof Startable) {
      ((Startable) messageProcessor).start();
    }
    if (filter instanceof Startable) {
      ((Startable) filter).start();
    }
  }

  public void stop() throws MuleException {
    if (messageProcessor instanceof Stoppable) {
      ((Stoppable) messageProcessor).stop();
    }
    if (filter instanceof Stoppable) {
      ((Stoppable) filter).stop();
    }
  }

  public void dispose() {
    if (messageProcessor instanceof Disposable) {
      ((Disposable) messageProcessor).dispose();
    }
    if (filter instanceof Disposable) {
      ((Disposable) filter).dispose();
    }
  }
}
