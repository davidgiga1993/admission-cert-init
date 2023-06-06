package main

import (
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/klog/v2"
)

type JsonPatch struct {
	Operation string `json:"op"`
	Path      string `json:"path"`
	Value     any    `json:"value"`
}

func PatchToBytes(patch []JsonPatch) []byte {
	bytes, err := json.Marshal(patch)
	if err != nil {
		klog.Error("Failed to marshal Patch", err)
		bytes = []byte("[]")
	}
	return bytes
}
