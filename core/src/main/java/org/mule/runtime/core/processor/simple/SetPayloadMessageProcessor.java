/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */

package org.mule.runtime.core.processor.simple;

import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.message.Message;
import org.mule.runtime.api.metadata.DataType;
import org.mule.runtime.api.metadata.DataTypeParamsBuilder;
import org.mule.runtime.api.metadata.TypedValue;
import org.mule.runtime.core.api.Event;
import org.mule.runtime.core.api.message.InternalMessage;
import org.mule.runtime.core.api.message.InternalMessage.Builder;
import org.mule.runtime.api.lifecycle.InitialisationException;
import org.mule.runtime.core.metadata.DefaultTypedValue;
import org.mule.runtime.core.util.AttributeEvaluator;

/**
 * Modifies the payload of a {@link Message} according to the provided value.
 */
public class SetPayloadMessageProcessor extends SimpleMessageProcessor {

  private DataType dataType;
  private AttributeEvaluator valueEvaluator = new AttributeEvaluator(null);


  @Override
  public Event process(Event event) throws MuleException {
    final Builder builder = InternalMessage.builder(event.getMessage());
    final org.mule.runtime.core.api.Event.Builder eventBuilder = Event.builder(event);

    if (dataType == null) {
      final TypedValue typedValue = resolveTypedValue(event, eventBuilder);
      builder.payload(typedValue.getValue()).mediaType(typedValue.getDataType().getMediaType());
    } else {
      Object value = resolveValue(event);
      final DataTypeParamsBuilder dataTypeBuilder =
          DataType.builder(dataType).type(value == null ? Object.class : value.getClass());
      builder.payload(value).mediaType(dataTypeBuilder.build().getMediaType());
    }

    return eventBuilder.message(builder.build()).build();
  }

  private Object resolveValue(Event event) {
    Object value;
    if (valueEvaluator.getRawValue() == null) {
      value = null;
    } else {
      value = valueEvaluator.resolveValue(event);
    }
    return value;
  }

  private TypedValue resolveTypedValue(Event event, Event.Builder eventBuilder) {
    if (valueEvaluator.getRawValue() == null) {
      return new DefaultTypedValue(null, DataType.OBJECT);
    } else {
      return valueEvaluator.resolveTypedValue(event, eventBuilder);
    }
  }

  public void setMimeType(String mimeType) {
    setDataType(DataType.builder(dataType == null ? DataType.OBJECT : dataType).mediaType(mimeType).build());
  }

  public void setEncoding(String encoding) {
    setDataType(DataType.builder(dataType == null ? DataType.OBJECT : dataType).charset(encoding).build());
  }

  public void setDataType(DataType dataType) {
    if (dataType.getMediaType().getCharset().isPresent()) {
      this.dataType = dataType;
    } else {
      this.dataType = DataType.builder(dataType).build();
    }
  }

  public void setValue(String value) {
    valueEvaluator = new AttributeEvaluator(value);
  }

  @Override
  public void initialise() throws InitialisationException {
    valueEvaluator.initialize(muleContext.getExpressionManager());
  }
}
