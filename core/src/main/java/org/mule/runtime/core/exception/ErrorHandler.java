/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.runtime.core.exception;

import static java.util.Collections.emptyList;
import static java.util.Collections.unmodifiableList;
import static org.mule.runtime.api.i18n.I18nMessageFactory.createStaticMessage;
import static org.mule.runtime.core.exception.ErrorTypeRepository.CRITICAL_ERROR_TYPE;
import static reactor.core.publisher.Mono.error;
import static reactor.core.publisher.Mono.just;

import java.util.List;
import java.util.Optional;

import org.mule.runtime.api.exception.MuleRuntimeException;
import org.mule.runtime.api.lifecycle.InitialisationException;
import org.mule.runtime.api.lifecycle.Lifecycle;
import org.mule.runtime.api.message.Error;
import org.mule.runtime.core.api.Event;
import org.mule.runtime.core.api.GlobalNameableObject;
import org.mule.runtime.core.api.context.MuleContextAware;
import org.mule.runtime.core.api.exception.MessagingExceptionHandler;
import org.mule.runtime.core.api.exception.MessagingExceptionHandlerAcceptor;
import org.mule.runtime.core.api.message.InternalMessage;
import org.mule.runtime.core.api.processor.MessageProcessorContainer;
import org.mule.runtime.core.api.processor.MessageProcessorPathElement;
import org.mule.runtime.core.message.DefaultExceptionPayload;
import org.mule.runtime.core.processor.AbstractMuleObjectOwner;

import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

/**
 * Selects which "on error" handler to execute based on filtering. Replaces the choice-exception-strategy from Mule 3. On error
 * handlers must implement {@link MessagingExceptionHandlerAcceptor} to be part of ErrorHandler.
 *
 * @since 4.0
 */
public class ErrorHandler extends AbstractMuleObjectOwner<MessagingExceptionHandlerAcceptor>
    implements MessagingExceptionHandlerAcceptor, MuleContextAware, Lifecycle, MessageProcessorContainer, GlobalNameableObject {

  private List<MessagingExceptionHandlerAcceptor> exceptionListeners;
  private ErrorTypeMatcher criticalMatcher = new SingleErrorTypeMatcher(CRITICAL_ERROR_TYPE);

  protected String globalName;

  @Override
  public String getGlobalName() {
    return globalName;
  }

  @Override
  public void setGlobalName(String globalName) {
    this.globalName = globalName;
  }

  @Override
  public Event handleException(MessagingException exception, Event event) {
    return Mono.from(apply(exception)).block();
  }

  @Override
  public Publisher<? extends Event> apply(MessagingException exception) {
    Event event = Event.builder(exception.getEvent())
        .message(InternalMessage.builder(exception.getEvent().getMessage())
            .exceptionPayload(new DefaultExceptionPayload(exception)).build())
        .build();
    if (isCriticalException(exception)) {
      return just(event);
    }
    for (MessagingExceptionHandlerAcceptor exceptionListener : exceptionListeners) {
      if (exceptionListener.accept(event)) {
        return exceptionListener.apply(new MessagingException(event, exception));
      }
    }
    return error(new MuleRuntimeException(createStaticMessage("Default exception strategy must accept any event.")));
  }

  private boolean isCriticalException(MessagingException exception) {
    Optional<Error> error = exception.getEvent().getError();
    return error.isPresent() && criticalMatcher.match(error.get().getErrorType());
  }

  public void setExceptionListeners(List<MessagingExceptionHandlerAcceptor> exceptionListeners) {
    this.exceptionListeners = exceptionListeners;
  }

  public List<MessagingExceptionHandlerAcceptor> getExceptionListeners() {
    return unmodifiableList(exceptionListeners);
  }

  @Override
  public void initialise() throws InitialisationException {
    addDefaultExceptionStrategyIfRequired();
    super.initialise();
    validateConfiguredExceptionStrategies();
  }

  private void addDefaultExceptionStrategyIfRequired() throws InitialisationException {
    if (!exceptionListeners.get(exceptionListeners.size() - 1).acceptsAll()) {
      String defaultErrorHandlerName = getMuleContext().getConfiguration().getDefaultErrorHandlerName();
      if (defaultErrorHandlerName != null && defaultErrorHandlerName.equals(this.getGlobalName())) {
        throw new InitialisationException(
                                          createStaticMessage("Default error-handler must include a final component that matches all errors."),
                                          this);
      }
      MessagingExceptionHandler defaultExceptionStrategy;
      try {
        defaultExceptionStrategy = getMuleContext().getDefaultErrorHandler();
      } catch (Exception e) {
        throw new InitialisationException(createStaticMessage("Failure initializing "
            + "error-handler. If error-handler is defined as default one "
            + "check that last exception strategy inside matches all errors"), e, this);
      }
      this.exceptionListeners.add(new MessagingExceptionStrategyAcceptorDelegate(defaultExceptionStrategy));
    }
  }

  @Override
  protected List<MessagingExceptionHandlerAcceptor> getOwnedObjects() {
    return exceptionListeners != null ? unmodifiableList(exceptionListeners) : emptyList();
  }

  private void validateConfiguredExceptionStrategies() {
    validateOnlyLastAcceptsAll();
  }

  private void validateOnlyLastAcceptsAll() {
    for (int i = 0; i < exceptionListeners.size() - 1; i++) {
      MessagingExceptionHandlerAcceptor messagingExceptionHandlerAcceptor = exceptionListeners.get(i);
      if (messagingExceptionHandlerAcceptor.acceptsAll()) {
        throw new MuleRuntimeException(
                                       createStaticMessage("Only last exception strategy inside <error-handler> can accept any message. Maybe expression attribute is empty."));
      }
    }
  }

  @Override
  public void addMessageProcessorPathElements(MessageProcessorPathElement pathElement) {
    int idx = 0;
    for (MessagingExceptionHandlerAcceptor listener : exceptionListeners) {
      if (listener instanceof MessageProcessorContainer) {
        MessageProcessorPathElement exceptionListener = pathElement.addChild(String.valueOf(idx));
        ((MessageProcessorContainer) listener).addMessageProcessorPathElements(exceptionListener);
      }
      idx++;
    }

  }

  @Override
  public boolean accept(Event event) {
    return true;
  }

  @Override
  public boolean acceptsAll() {
    return true;
  }
}
