package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/kubevirt"

	imageutils "k8s.io/kubernetes/test/utils/image"

	"github.com/openshift-eng/openshift-tests-extension/pkg/extension"
)

// requiredImage associates an e2e image pullspec with an index used to generate
// the image tag so that it matches with the tag in quay.io/openshift/community-e2e-images.
type requiredImage struct {
	pullSpec string
	index    int
}

var requiredImages []requiredImage

// Match Origin's approved VM image in test/extended/util/image/image.go and
// test/extended/networking/livemigration.go. Keep the upstream default intact.
const fedoraContainerDiskImage = "quay.io/kubevirt/fedora-with-test-tooling-container-disk:v1.8.2"

func init() {
	agnhostImage := requiredImage{
		pullSpec: imageutils.GetE2EImage(imageutils.Agnhost),
		index:    int(imageutils.Agnhost),
	}
	requiredImages = append(requiredImages, agnhostImage)
	requiredImages = append(requiredImages,
		// Origin uses -1 for non-Kubernetes images: omit the index from the
		// mirror tag, matching image.LocationFor in the Origin VM tests.
		requiredImage{pullSpec: fedoraContainerDiskImage, index: -1},
	)
}

// registerTestImages advertises OVN-Kubernetes e2e images to the openshift-tests
// extension so origin can list and mirror them (see "images" subcommand).
func registerTestImages(ext *extension.Extension) error {
	fedoraImage, err := mappedTestImage(fedoraContainerDiskImage, os.Getenv("KUBE_TEST_REPO"))
	if err != nil {
		return err
	}
	kubevirt.FedoraWithTestToolingContainerDiskImage = fedoraImage
	for _, ri := range requiredImages {
		img, err := extensionImageFromPullSpec(ri.pullSpec)
		if err != nil {
			return fmt.Errorf("failed to register test image %q: %v", ri.pullSpec, err)
		}
		img.Index = ri.index
		ext.RegisterImage(img)
	}
	return nil
}

// mappedTestImage follows Origin's GetMappedImages for images with index -1.
// Kubernetes calls that sentinel None (0); both produce the same index-free
// tag. An empty repository preserves the source image.
func mappedTestImage(pullSpec, repo string) (string, error) {
	if repo == "" {
		return pullSpec, nil
	}
	registry, repository, ok := strings.Cut(repo, "/")
	if !ok || registry == "" || repository == "" {
		return "", fmt.Errorf("KUBE_TEST_REPO must include a registry and repository: %q", repo)
	}
	img, err := extensionImageFromPullSpec(pullSpec)
	if err != nil {
		return "", err
	}
	var config imageutils.Config
	config.SetRegistry(img.Registry)
	config.SetName(img.Name)
	config.SetVersion(img.Version)
	mapped := imageutils.GetMappedImageConfigs(map[imageutils.ImageID]imageutils.Config{imageutils.None: config}, repo)[imageutils.None]
	return mapped.GetE2EImage(), nil
}

// extensionImageFromPullSpec splits a pullspec into the registry/name/version
// layout expected by k8s.io/kubernetes/test/utils/image.Config.GetE2EImage
// (fmt.Sprintf("%s/%s:%s", registry, name, version)).
func extensionImageFromPullSpec(pullSpec string) (extension.Image, error) {
	registry, name, version, err := splitImagePullSpec(pullSpec)
	if err != nil {
		return extension.Image{}, err
	}
	return extension.Image{
		Registry: registry,
		Name:     name,
		Version:  version,
	}, nil
}

func splitImagePullSpec(pullSpec string) (registry, name, version string, err error) {
	if pullSpec == "" {
		return "", "", "", fmt.Errorf("empty image pullspec")
	}
	if strings.Contains(pullSpec, "@") {
		return "", "", "", fmt.Errorf("digest image pullspecs are not supported: %q", pullSpec)
	}

	remainder := pullSpec
	if tagIndex := strings.LastIndex(pullSpec, ":"); tagIndex > strings.LastIndex(pullSpec, "/") {
		version = pullSpec[tagIndex+1:]
		remainder = pullSpec[:tagIndex]
	}
	if version == "" {
		version = "latest"
	}

	first, rest, ok := strings.Cut(remainder, "/")
	if !ok {
		// Short docker-library name, e.g. "nginx" → docker.io/library/nginx
		return "docker.io", "library/" + remainder, version, nil
	}

	if strings.ContainsAny(first, ".:") || first == "localhost" {
		// Explicit registry, e.g. "quay.io/foo/bar", "registry.k8s.io/...",
		// or "localhost:5000/ovn/test"
		return first, rest, version, nil
	}

	// Docker Hub user/org image, e.g. "cloudflare/goflow"
	return "docker.io", remainder, version, nil
}
