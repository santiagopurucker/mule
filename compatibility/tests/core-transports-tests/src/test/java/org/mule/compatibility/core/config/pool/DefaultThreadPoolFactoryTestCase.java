/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.compatibility.core.config.pool;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mule.compatibility.core.api.config.MuleEndpointProperties.OBJECT_DEFAULT_THREADING_PROFILE;

import org.mule.compatibility.core.api.config.ThreadingProfile;
import org.mule.tck.junit4.AbstractMuleContextEndpointTestCase;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

public class DefaultThreadPoolFactoryTestCase extends AbstractMuleContextEndpointTestCase {

  @Test
  public void defaultThreadPoolFactory() throws Exception {
    final ThreadingProfile tp = muleContext.getRegistry().lookupObject(OBJECT_DEFAULT_THREADING_PROFILE);
    final ThreadPoolFactory pf = tp.getPoolFactory();
    assertThat(pf, instanceOf(DefaultThreadPoolFactory.class));
  }

  @Test
  public void threadPoolDefaults() throws Exception {
    final ThreadingProfile threadingProfile = muleContext.getRegistry().lookupObject(OBJECT_DEFAULT_THREADING_PROFILE);
    final ExecutorService executorService = threadingProfile.createPool("sapo pepe");
    assertThat(executorService, notNullValue());
    assertThat(executorService, instanceOf(ThreadPoolExecutor.class));
    ThreadPoolExecutor pool = (ThreadPoolExecutor) executorService;
    assertThat(pool.getMaximumPoolSize(), is(threadingProfile.getMaxThreadsActive()));
    assertThat(pool.getCorePoolSize(), is(threadingProfile.getMaxThreadsIdle()));
    assertThat(pool.getKeepAliveTime(TimeUnit.MILLISECONDS), is(threadingProfile.getThreadTTL()));
  }

  @Test
  public void scheduledThreadPoolDefaults() throws Exception {
    ThreadingProfile threadingProfile = muleContext.getRegistry().lookupObject(OBJECT_DEFAULT_THREADING_PROFILE);
    ScheduledExecutorService executorService = threadingProfile.createScheduledPool("sapo pepe");
    assertThat(executorService, notNullValue());
    assertThat(executorService, instanceOf(ScheduledThreadPoolExecutor.class));
    ScheduledThreadPoolExecutor scheduledPool = (ScheduledThreadPoolExecutor) executorService;
    assertThat(scheduledPool.getContinueExistingPeriodicTasksAfterShutdownPolicy(), is(false));
    assertThat(scheduledPool.getExecuteExistingDelayedTasksAfterShutdownPolicy(), is(true));
    assertThat(scheduledPool.getCorePoolSize(), is(threadingProfile.getMaxThreadsIdle()));
    assertThat(scheduledPool.getKeepAliveTime(TimeUnit.MILLISECONDS), is(threadingProfile.getThreadTTL()));
  }

  @Test
  public void scheduledThreadPoolRejectHandler() throws Exception {
    ThreadingProfile threadingProfile = muleContext.getRegistry().lookupObject(OBJECT_DEFAULT_THREADING_PROFILE);
    ThreadPoolExecutor.DiscardOldestPolicy expectedRejectedExecutionHandler = new ThreadPoolExecutor.DiscardOldestPolicy();
    threadingProfile.setRejectedExecutionHandler(expectedRejectedExecutionHandler);
    ScheduledExecutorService executorService = threadingProfile.createScheduledPool("sapo pepe");
    ScheduledThreadPoolExecutor scheduledPool = (ScheduledThreadPoolExecutor) executorService;
    assertThat(scheduledPool.getRejectedExecutionHandler(), is((RejectedExecutionHandler) expectedRejectedExecutionHandler));
  }
}
