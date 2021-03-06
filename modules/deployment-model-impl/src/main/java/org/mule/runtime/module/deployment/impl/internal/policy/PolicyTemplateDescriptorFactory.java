/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */

package org.mule.runtime.module.deployment.impl.internal.policy;

import static java.io.File.separator;
import static java.lang.String.format;
import static org.mule.runtime.deployment.model.api.policy.PolicyTemplateDescriptor.DEFAULT_POLICY_CONFIGURATION_RESOURCE;
import static org.mule.runtime.deployment.model.api.policy.PolicyTemplateDescriptor.META_INF;
import static org.mule.runtime.deployment.model.api.policy.PolicyTemplateDescriptor.MULE_POLICY_JSON;
import org.mule.runtime.api.deployment.meta.MuleArtifactLoaderDescriptor;
import org.mule.runtime.api.deployment.meta.MulePolicyModel;
import org.mule.runtime.api.deployment.persistence.MulePolicyModelJsonSerializer;
import org.mule.runtime.deployment.model.api.policy.PolicyTemplateDescriptor;
import org.mule.runtime.module.artifact.descriptor.ArtifactDescriptorCreateException;
import org.mule.runtime.module.artifact.descriptor.ArtifactDescriptorFactory;
import org.mule.runtime.module.artifact.descriptor.ClassLoaderModel;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;

/**
 * Creates descriptors for policy templates
 */
public class PolicyTemplateDescriptorFactory implements ArtifactDescriptorFactory<PolicyTemplateDescriptor> {

  public static final String PROPERTIES_BUNDLE_DESCRIPTOR_LOADER_ID = "PROPERTIES";
  protected static final String FILE_SYSTEM_MODEL_LOADER_ID = "FILE_SYSTEM";
  protected static final String MISSING_POLICY_DESCRIPTOR_ERROR = "Policy must contain a " + MULE_POLICY_JSON + " file";

  @Override
  public PolicyTemplateDescriptor create(File artifactFolder) throws ArtifactDescriptorCreateException {
    final File policyJsonFile = new File(artifactFolder, META_INF + separator + MULE_POLICY_JSON);
    if (!policyJsonFile.exists()) {
      throw new ArtifactDescriptorCreateException(MISSING_POLICY_DESCRIPTOR_ERROR);
    }

    final MulePolicyModel mulePolicyModel = getMulePolicyJsonDescriber(policyJsonFile);

    final PolicyTemplateDescriptor descriptor = new PolicyTemplateDescriptor(mulePolicyModel.getName());
    descriptor.setRootFolder(artifactFolder);
    descriptor.setConfigResourceFiles(new File[] {new File(artifactFolder, DEFAULT_POLICY_CONFIGURATION_RESOURCE)});

    if (mulePolicyModel.getClassLoaderModelLoaderDescriptor().isPresent()) {
      MuleArtifactLoaderDescriptor muleArtifactLoaderDescriptor = mulePolicyModel.getClassLoaderModelLoaderDescriptor().get();
      if (!muleArtifactLoaderDescriptor.getId().equals(FILE_SYSTEM_MODEL_LOADER_ID)) {
        throw new ArtifactDescriptorCreateException("Unknown model loader: " + muleArtifactLoaderDescriptor.getId());
      }

      FileSystemPolicyClassLoaderModelLoader classLoaderModelLoader = new FileSystemPolicyClassLoaderModelLoader();
      ClassLoaderModel classLoaderModel =
          classLoaderModelLoader.loadClassLoaderModel(artifactFolder);
      descriptor.setClassLoaderModel(classLoaderModel);
    }

    MuleArtifactLoaderDescriptor bundleDescriptorLoader = mulePolicyModel.getBundleDescriptorLoader();
    if (!bundleDescriptorLoader.getId().equals(PROPERTIES_BUNDLE_DESCRIPTOR_LOADER_ID)) {
      throw new ArtifactDescriptorCreateException("Unknown bundle descriptor loader: " + bundleDescriptorLoader.getId());
    }

    PropertiesBundleDescriptorLoader propertiesBundleDescriptorLoader = new PropertiesBundleDescriptorLoader();
    descriptor.setBundleDescriptor(propertiesBundleDescriptorLoader.loadBundleDescriptor(bundleDescriptorLoader.getAttributes()));

    return descriptor;
  }

  private MulePolicyModel getMulePolicyJsonDescriber(File jsonFile) {
    try (InputStream stream = new FileInputStream(jsonFile)) {
      return new MulePolicyModelJsonSerializer().deserialize(IOUtils.toString(stream));
    } catch (IOException e) {
      throw new IllegalArgumentException(format("Could not read extension describer on plugin '%s'", jsonFile.getAbsolutePath()),
                                         e);
    }
  }
}
