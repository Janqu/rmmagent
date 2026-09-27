//go:build windows

package agent

import (
	"strings"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

func (a *Agent) SecurityInventory() []rmm.SecurityProductInventory {
	products := make([]rmm.SecurityProductInventory, 0)
	seen := map[string]int{}

	if avs, err := GetAntivirusInventory(); err == nil {
		for _, av := range avs {
			vendor, category := classifySecurityProduct(av.DisplayName + " " + av.PathToSignedProductExe)
			product := rmm.SecurityProductInventory{
				Name:         av.DisplayName,
				Vendor:       vendor,
				Category:     category,
				Healthy:      antivirusProductHealthy(av.ProductState),
				Running:      antivirusProductRunning(av.ProductState),
				ProductState: av.ProductState,
				Path:         av.PathToSignedProductExe,
				Timestamp:    av.Timestamp,
			}
			idx := len(products)
			seen[strings.ToLower(product.Name)] = idx
			seen[strings.ToLower(product.Vendor)] = idx
			products = append(products, product)
		}
	}

	for _, svc := range a.GetServices() {
		vendor, category := classifySecurityProduct(svc.Name + " " + svc.DisplayName + " " + svc.Description + " " + svc.BinPath)
		if vendor == "Unknown" {
			continue
		}
		key := strings.ToLower(vendor)
		idx, ok := seen[key]
		if !ok {
			products = append(products, rmm.SecurityProductInventory{
				Name:     vendor,
				Vendor:   vendor,
				Category: category,
				Healthy:  svc.Status == "running",
				Running:  svc.Status == "running",
				Services: []string{svc.Name + ":" + svc.Status},
			})
			seen[key] = len(products) - 1
			continue
		}
		products[idx].Services = append(products[idx].Services, svc.Name+":"+svc.Status)
		if svc.Status == "running" {
			products[idx].Running = true
			products[idx].Healthy = true
		}
	}

	return products
}

func antivirusProductRunning(state uint32) bool {
	return state != 0
}

func antivirusProductHealthy(state uint32) bool {
	return state != 0
}
