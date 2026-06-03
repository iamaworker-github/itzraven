---
name: "scitex-nn"
description: "PyTorch neural-network building blocks for neuroscience and signal processing. Differentiable filters (`BandPassFilter`, `BandStopFilter`, `HighPassFilter`, `LowPassFilter`, `GaussianFilter`, `Differe"
category: network-security
subcategory: network-security
tags: []
relevance: 0
source: ""
author: ""
license: ""
---
# scitex-nn


## Description
PyTorch neural-network building blocks for neuroscience and signal processing. Differentiable filters (`BandPassFilter`, `BandStopFilter`, `HighPassFilter`, `LowPassFilter`, `GaussianFilter`, `DifferentiableBandPassFilter`) operate on 1D channels-first tensors. `Hilbert` provides differentiable Hilbert transform for analytic-signal extraction. Architecture blocks: `BNet` / `BNet_Res` (B-shaped backbone with optional residual connections), `BHead` (decoder head). Augmentation/regularization: `AxiswiseDropout`, `DropoutChannels`, `ChannelGainChanger`, `FreqGainChanger` (gain perturbation in time and frequency domains for SSL training). Drop-in replacement for hand-rolled `torch.nn.Conv1d` butterworth-init wrappers, scattered Hilbert implementations using `torch.fft`, and bespoke channel-dropout layers. Use whenever a model needs trainable filter banks, differentiable spectral features, or SSL-style time/frequency augmentation.


## Relevance Score
0
