package dsl

import "ulpf/runtime/internal/spec"

func specTS(kind string) spec.TSFormat { return spec.TSFormat{Kind: kind} }
