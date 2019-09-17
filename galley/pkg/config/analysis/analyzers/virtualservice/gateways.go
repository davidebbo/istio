// Copyright 2019 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package virtualservice

import (
	"istio.io/api/networking/v1alpha3"

	"istio.io/istio/galley/pkg/config/analysis"
	"istio.io/istio/galley/pkg/config/analysis/msg"
	"istio.io/istio/galley/pkg/config/processor/metadata"
	"istio.io/istio/galley/pkg/config/resource"
	"k8s.io/api/admissionregistration/v1beta1"
	v1 "k8s.io/api/core/v1"
)

// GatewayAnalyzer checks the gateways associated with each virtual service
type GatewayAnalyzer struct{}

var _ analysis.Analyzer = &GatewayAnalyzer{}

// Name implements Analyzer
func (s *GatewayAnalyzer) Name() string {
	return "virtualservice.GatewayAnalyzer"
}

// Analyze implements Analyzer
func (s *GatewayAnalyzer) Analyze(c analysis.Context) {
	c.ForEach(metadata.IstioNetworkingV1Alpha3Virtualservices, func(r *resource.Entry) bool {
		s.analyzeVirtualService(r, c)
		return true
	})

	c.ForEach(metadata.K8SCoreV1Pods, func(r *resource.Entry) bool {
		s.analyzePod(r, c)
		return true
	})

	c.ForEach(metadata.K8SCoreV1Beta1Mutatingwebhookconfigurations, func(r *resource.Entry) bool {
		s.analyzeMutatingwebhookconfiguration(r, c)
		return true
	})
}

func (s *GatewayAnalyzer) analyzeVirtualService(r *resource.Entry, c analysis.Context) {
	vs := r.Item.(*v1alpha3.VirtualService)

	ns, _ := r.Metadata.Name.InterpretAsNamespaceAndName()
	for _, gwName := range vs.Gateways {
		if !c.Exists(metadata.IstioNetworkingV1Alpha3Gateways, resource.NewName(ns, gwName)) {
			c.Report(metadata.IstioNetworkingV1Alpha3Virtualservices, msg.NewReferencedResourceNotFound(r, "gateway", gwName))
		}
	}
}

func (s *GatewayAnalyzer) analyzePod(r *resource.Entry, c analysis.Context) {
	pod := r.Item.(*v1.Pod)

	if len(pod.Spec.InitContainers) == 1 {
		c.Report(metadata.K8SCoreV1Pods, msg.NewInternalError(r, pod.Spec.InitContainers[0].Image))
	}
}

func (s *GatewayAnalyzer) analyzeMutatingwebhookconfiguration(r *resource.Entry, c analysis.Context) {
	hookConfig := r.Item.(*v1beta1.MutatingWebhookConfiguration)
	if hookConfig.Name == "istio-sidecar-injector" {
		matchLabels := hookConfig.Webhooks[0].NamespaceSelector.MatchLabels
		for key := range matchLabels {
			c.Report(metadata.K8SCoreV1Beta1Mutatingwebhookconfigurations, msg.NewInternalError(r, key+":"+matchLabels[key]))
		}
	}
}
