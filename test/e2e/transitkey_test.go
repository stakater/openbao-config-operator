package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/test/utils"
)

var _ = Describe("OpenBaoTransitKey CR → OpenBao", Ordered, func() {
	const (
		seName    = "e2e-transit-engine"
		keyName   = "e2e-transit-key"
		keyBadCR  = "e2e-transit-key-invalid"
		mountPath = "e2e-transit"
		baoKey    = "e2e-key"
	)

	var (
		k8s        client.Client
		bao        baoclient.Client
		nn         types.NamespacedName
		seTeardown func(context.Context)
	)

	boolPtr := func(b bool) *bool { return &b }

	BeforeAll(func(ctx SpecContext) {
		k8s = utils.GetK8sClient()
		bao = utils.NewTypedBaoClient()
		nn = types.NamespacedName{Namespace: OperatorNS, Name: keyName}

		seTeardown = ensureSecretEngine(ctx, k8s, bao, seName, mountPath,
			v1alpha1.OpenBaoSecretEngineSpec{Transit: &v1alpha1.TransitSpec{}})
	})

	AfterAll(func(ctx SpecContext) { seTeardown(ctx) })

	It("creates a TransitKey CR and sees the key in OpenBao", func(ctx SpecContext) {
		deleteIfExists(ctx, k8s, &v1alpha1.OpenBaoTransitKey{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: keyName},
		}, nn)

		cr := &v1alpha1.OpenBaoTransitKey{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: keyName},
			Spec: v1alpha1.OpenBaoTransitKeySpec{
				Path:            mountPath,
				Name:            baoKey,
				Type:            "aes256-gcm96",
				DeletionAllowed: boolPtr(true),
			},
		}
		Expect(k8s.Create(ctx, cr)).To(Succeed())
		// Cleanup is owned by the "deletes" spec — see secretengine_test.go.

		Eventually(func(g Gomega) {
			info, err := bao.ReadTransitKey(ctx, mountPath, baoKey)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(info.Type).To(Equal("aes256-gcm96"))
			g.Expect(info.DeletionAllowed).To(BeTrue())
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())

		expectReady(ctx, k8s, &v1alpha1.OpenBaoTransitKey{}, nn)
	})

	It("updates auto-rotate period when the CR is patched", func(ctx SpecContext) {
		patchSpec(ctx, k8s, nn, &v1alpha1.OpenBaoTransitKey{}, func(cur *v1alpha1.OpenBaoTransitKey) {
			cur.Spec.AutoRotatePeriod = "720h"
		})

		Eventually(func(g Gomega) {
			info, err := bao.ReadTransitKey(ctx, mountPath, baoKey)
			g.Expect(err).NotTo(HaveOccurred())
			// 720h == 2592000s
			g.Expect(info.AutoRotatePeriod).To(Equal(2592000))
		}).WithTimeout(60 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
	})

	// Deleting the CR must release the finalizer without touching the bao
	// key. The key holds the only material that decrypts anything encrypted
	// under it, so it outlives its CR; the mount teardown in AfterAll is
	// what removes it at the end of the suite.
	It("leaves the transit key in OpenBao when the CR is deleted", func(ctx SpecContext) {
		Expect(k8s.Delete(ctx, &v1alpha1.OpenBaoTransitKey{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: keyName},
		})).To(Succeed())

		expectGone(ctx, k8s, &v1alpha1.OpenBaoTransitKey{}, nn)

		info, err := bao.ReadTransitKey(ctx, mountPath, baoKey)
		Expect(err).NotTo(HaveOccurred(), "bao key must survive CR deletion")
		Expect(info.Type).To(Equal("aes256-gcm96"))
	})

	It("rejects convergentEncryption without derived=true", func(ctx SpecContext) {
		bad := &v1alpha1.OpenBaoTransitKey{
			ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: keyBadCR},
			Spec: v1alpha1.OpenBaoTransitKeySpec{
				Path:                 mountPath,
				Name:                 "e2e-key-bad",
				Type:                 "aes256-gcm96",
				ConvergentEncryption: boolPtr(true),
			},
		}
		Expect(k8s.Create(ctx, bad)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			_ = k8s.Delete(ctx, &v1alpha1.OpenBaoTransitKey{
				ObjectMeta: metav1.ObjectMeta{Namespace: OperatorNS, Name: keyBadCR},
			})
		})

		expectReadyFalse(ctx, k8s, &v1alpha1.OpenBaoTransitKey{},
			types.NamespacedName{Namespace: OperatorNS, Name: keyBadCR},
			"Invalid", "derived")
	})
})
