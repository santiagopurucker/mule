/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.runtime.core.api.util;

import static java.lang.String.format;
import static org.apache.commons.lang.builder.EqualsBuilder.reflectionEquals;
import static org.apache.commons.lang.builder.HashCodeBuilder.reflectionHashCode;
import static org.mule.runtime.api.util.Preconditions.checkArgument;

/**
 * A convenience class to represent value pairs.
 *
 * @param <K> the type of the first element.
 * @param <V> the type of the second element.
 */
public final class Pair<K, V> {

  /**
   * Key of this {@link Pair}.
   */
  private final K first;

  /**
   * Value of this {@link Pair}.
   */
  private final V second;

  /**
   * Creates a new pair
   *
   * @param first  The first element of this pair
   * @param second The second element of this pair
   */
  public Pair(K first, V second) {
    checkArgument(first != null, "the first value cannot be null");
    checkArgument(second != null, "the second value cannot be null");
    this.first = first;
    this.second = second;
  }

  /**
   * @return the second of the first element of this {@link Pair}.
   */
  public K getFirst() {
    return first;
  }

  /**
   * @return the second of the second element of this {@link Pair}.
   */
  public V getSecond() {
    return second;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String toString() {
    return format("{%s:%s}", first, second);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public int hashCode() {
    return reflectionHashCode(this);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean equals(Object other) {
    return reflectionEquals(this, other);
  }
}
