// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/config/overload/v2alpha/overload.proto

package envoy_config_overload_v2alpha

import (
	fmt "fmt"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
	any "github.com/golang/protobuf/ptypes/any"
	duration "github.com/golang/protobuf/ptypes/duration"
	_struct "github.com/golang/protobuf/ptypes/struct"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type ResourceMonitor struct {
	// The name of the resource monitor to instantiate. Must match a registered
	// resource monitor type. The built-in resource monitors are:
	//
	// * :ref:`envoy.resource_monitors.fixed_heap
	//   <envoy_api_msg_config.resource_monitor.fixed_heap.v2alpha.FixedHeapConfig>`
	// * :ref:`envoy.resource_monitors.injected_resource
	//   <envoy_api_msg_config.resource_monitor.injected_resource.v2alpha.InjectedResourceConfig>`
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Configuration for the resource monitor being instantiated.
	//
	// Types that are valid to be assigned to ConfigType:
	//	*ResourceMonitor_Config
	//	*ResourceMonitor_TypedConfig
	ConfigType           isResourceMonitor_ConfigType `protobuf_oneof:"config_type"`
	XXX_NoUnkeyedLiteral struct{}                     `json:"-"`
	XXX_unrecognized     []byte                       `json:"-"`
	XXX_sizecache        int32                        `json:"-"`
}

func (m *ResourceMonitor) Reset()         { *m = ResourceMonitor{} }
func (m *ResourceMonitor) String() string { return proto.CompactTextString(m) }
func (*ResourceMonitor) ProtoMessage()    {}
func (*ResourceMonitor) Descriptor() ([]byte, []int) {
	return fileDescriptor_c3380c1aa89ddd52, []int{0}
}

func (m *ResourceMonitor) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ResourceMonitor.Unmarshal(m, b)
}
func (m *ResourceMonitor) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ResourceMonitor.Marshal(b, m, deterministic)
}
func (m *ResourceMonitor) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ResourceMonitor.Merge(m, src)
}
func (m *ResourceMonitor) XXX_Size() int {
	return xxx_messageInfo_ResourceMonitor.Size(m)
}
func (m *ResourceMonitor) XXX_DiscardUnknown() {
	xxx_messageInfo_ResourceMonitor.DiscardUnknown(m)
}

var xxx_messageInfo_ResourceMonitor proto.InternalMessageInfo

func (m *ResourceMonitor) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type isResourceMonitor_ConfigType interface {
	isResourceMonitor_ConfigType()
}

type ResourceMonitor_Config struct {
	Config *_struct.Struct `protobuf:"bytes,2,opt,name=config,proto3,oneof"`
}

type ResourceMonitor_TypedConfig struct {
	TypedConfig *any.Any `protobuf:"bytes,3,opt,name=typed_config,json=typedConfig,proto3,oneof"`
}

func (*ResourceMonitor_Config) isResourceMonitor_ConfigType() {}

func (*ResourceMonitor_TypedConfig) isResourceMonitor_ConfigType() {}

func (m *ResourceMonitor) GetConfigType() isResourceMonitor_ConfigType {
	if m != nil {
		return m.ConfigType
	}
	return nil
}

// Deprecated: Do not use.
func (m *ResourceMonitor) GetConfig() *_struct.Struct {
	if x, ok := m.GetConfigType().(*ResourceMonitor_Config); ok {
		return x.Config
	}
	return nil
}

func (m *ResourceMonitor) GetTypedConfig() *any.Any {
	if x, ok := m.GetConfigType().(*ResourceMonitor_TypedConfig); ok {
		return x.TypedConfig
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*ResourceMonitor) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*ResourceMonitor_Config)(nil),
		(*ResourceMonitor_TypedConfig)(nil),
	}
}

type ThresholdTrigger struct {
	// If the resource pressure is greater than or equal to this value, the trigger
	// will fire.
	Value                float64  `protobuf:"fixed64,1,opt,name=value,proto3" json:"value,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ThresholdTrigger) Reset()         { *m = ThresholdTrigger{} }
func (m *ThresholdTrigger) String() string { return proto.CompactTextString(m) }
func (*ThresholdTrigger) ProtoMessage()    {}
func (*ThresholdTrigger) Descriptor() ([]byte, []int) {
	return fileDescriptor_c3380c1aa89ddd52, []int{1}
}

func (m *ThresholdTrigger) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ThresholdTrigger.Unmarshal(m, b)
}
func (m *ThresholdTrigger) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ThresholdTrigger.Marshal(b, m, deterministic)
}
func (m *ThresholdTrigger) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ThresholdTrigger.Merge(m, src)
}
func (m *ThresholdTrigger) XXX_Size() int {
	return xxx_messageInfo_ThresholdTrigger.Size(m)
}
func (m *ThresholdTrigger) XXX_DiscardUnknown() {
	xxx_messageInfo_ThresholdTrigger.DiscardUnknown(m)
}

var xxx_messageInfo_ThresholdTrigger proto.InternalMessageInfo

func (m *ThresholdTrigger) GetValue() float64 {
	if m != nil {
		return m.Value
	}
	return 0
}

type Trigger struct {
	// The name of the resource this is a trigger for.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Types that are valid to be assigned to TriggerOneof:
	//	*Trigger_Threshold
	TriggerOneof         isTrigger_TriggerOneof `protobuf_oneof:"trigger_oneof"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *Trigger) Reset()         { *m = Trigger{} }
func (m *Trigger) String() string { return proto.CompactTextString(m) }
func (*Trigger) ProtoMessage()    {}
func (*Trigger) Descriptor() ([]byte, []int) {
	return fileDescriptor_c3380c1aa89ddd52, []int{2}
}

func (m *Trigger) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Trigger.Unmarshal(m, b)
}
func (m *Trigger) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Trigger.Marshal(b, m, deterministic)
}
func (m *Trigger) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Trigger.Merge(m, src)
}
func (m *Trigger) XXX_Size() int {
	return xxx_messageInfo_Trigger.Size(m)
}
func (m *Trigger) XXX_DiscardUnknown() {
	xxx_messageInfo_Trigger.DiscardUnknown(m)
}

var xxx_messageInfo_Trigger proto.InternalMessageInfo

func (m *Trigger) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type isTrigger_TriggerOneof interface {
	isTrigger_TriggerOneof()
}

type Trigger_Threshold struct {
	Threshold *ThresholdTrigger `protobuf:"bytes,2,opt,name=threshold,proto3,oneof"`
}

func (*Trigger_Threshold) isTrigger_TriggerOneof() {}

func (m *Trigger) GetTriggerOneof() isTrigger_TriggerOneof {
	if m != nil {
		return m.TriggerOneof
	}
	return nil
}

func (m *Trigger) GetThreshold() *ThresholdTrigger {
	if x, ok := m.GetTriggerOneof().(*Trigger_Threshold); ok {
		return x.Threshold
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*Trigger) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*Trigger_Threshold)(nil),
	}
}

type OverloadAction struct {
	// The name of the overload action. This is just a well-known string that listeners can
	// use for registering callbacks. Custom overload actions should be named using reverse
	// DNS to ensure uniqueness.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// A set of triggers for this action. If any of these triggers fire the overload action
	// is activated. Listeners are notified when the overload action transitions from
	// inactivated to activated, or vice versa.
	Triggers             []*Trigger `protobuf:"bytes,2,rep,name=triggers,proto3" json:"triggers,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *OverloadAction) Reset()         { *m = OverloadAction{} }
func (m *OverloadAction) String() string { return proto.CompactTextString(m) }
func (*OverloadAction) ProtoMessage()    {}
func (*OverloadAction) Descriptor() ([]byte, []int) {
	return fileDescriptor_c3380c1aa89ddd52, []int{3}
}

func (m *OverloadAction) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_OverloadAction.Unmarshal(m, b)
}
func (m *OverloadAction) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_OverloadAction.Marshal(b, m, deterministic)
}
func (m *OverloadAction) XXX_Merge(src proto.Message) {
	xxx_messageInfo_OverloadAction.Merge(m, src)
}
func (m *OverloadAction) XXX_Size() int {
	return xxx_messageInfo_OverloadAction.Size(m)
}
func (m *OverloadAction) XXX_DiscardUnknown() {
	xxx_messageInfo_OverloadAction.DiscardUnknown(m)
}

var xxx_messageInfo_OverloadAction proto.InternalMessageInfo

func (m *OverloadAction) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *OverloadAction) GetTriggers() []*Trigger {
	if m != nil {
		return m.Triggers
	}
	return nil
}

type OverloadManager struct {
	// The interval for refreshing resource usage.
	RefreshInterval *duration.Duration `protobuf:"bytes,1,opt,name=refresh_interval,json=refreshInterval,proto3" json:"refresh_interval,omitempty"`
	// The set of resources to monitor.
	ResourceMonitors []*ResourceMonitor `protobuf:"bytes,2,rep,name=resource_monitors,json=resourceMonitors,proto3" json:"resource_monitors,omitempty"`
	// The set of overload actions.
	Actions              []*OverloadAction `protobuf:"bytes,3,rep,name=actions,proto3" json:"actions,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *OverloadManager) Reset()         { *m = OverloadManager{} }
func (m *OverloadManager) String() string { return proto.CompactTextString(m) }
func (*OverloadManager) ProtoMessage()    {}
func (*OverloadManager) Descriptor() ([]byte, []int) {
	return fileDescriptor_c3380c1aa89ddd52, []int{4}
}

func (m *OverloadManager) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_OverloadManager.Unmarshal(m, b)
}
func (m *OverloadManager) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_OverloadManager.Marshal(b, m, deterministic)
}
func (m *OverloadManager) XXX_Merge(src proto.Message) {
	xxx_messageInfo_OverloadManager.Merge(m, src)
}
func (m *OverloadManager) XXX_Size() int {
	return xxx_messageInfo_OverloadManager.Size(m)
}
func (m *OverloadManager) XXX_DiscardUnknown() {
	xxx_messageInfo_OverloadManager.DiscardUnknown(m)
}

var xxx_messageInfo_OverloadManager proto.InternalMessageInfo

func (m *OverloadManager) GetRefreshInterval() *duration.Duration {
	if m != nil {
		return m.RefreshInterval
	}
	return nil
}

func (m *OverloadManager) GetResourceMonitors() []*ResourceMonitor {
	if m != nil {
		return m.ResourceMonitors
	}
	return nil
}

func (m *OverloadManager) GetActions() []*OverloadAction {
	if m != nil {
		return m.Actions
	}
	return nil
}

func init() {
	proto.RegisterType((*ResourceMonitor)(nil), "envoy.config.overload.v2alpha.ResourceMonitor")
	proto.RegisterType((*ThresholdTrigger)(nil), "envoy.config.overload.v2alpha.ThresholdTrigger")
	proto.RegisterType((*Trigger)(nil), "envoy.config.overload.v2alpha.Trigger")
	proto.RegisterType((*OverloadAction)(nil), "envoy.config.overload.v2alpha.OverloadAction")
	proto.RegisterType((*OverloadManager)(nil), "envoy.config.overload.v2alpha.OverloadManager")
}

func init() {
	proto.RegisterFile("envoy/config/overload/v2alpha/overload.proto", fileDescriptor_c3380c1aa89ddd52)
}

var fileDescriptor_c3380c1aa89ddd52 = []byte{
	// 495 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x52, 0x4f, 0x8b, 0xd3, 0x40,
	0x14, 0xcf, 0xa4, 0xfb, 0xa7, 0x3b, 0xb1, 0xb6, 0x0e, 0x85, 0xa6, 0xeb, 0x1f, 0x4a, 0x0e, 0x52,
	0xd1, 0x4d, 0xa0, 0xe2, 0xc1, 0x8b, 0xd2, 0x71, 0xc1, 0x0a, 0x2e, 0xbb, 0xc4, 0xbd, 0x87, 0xd9,
	0x66, 0x9a, 0x06, 0xb2, 0x33, 0x65, 0x32, 0x09, 0x06, 0x3f, 0x80, 0x27, 0x2f, 0x7e, 0x11, 0xbf,
	0x9a, 0x47, 0xe9, 0x49, 0x32, 0x33, 0xa9, 0x6e, 0x17, 0xda, 0x9c, 0xc2, 0xfb, 0xfd, 0x79, 0xbf,
	0x79, 0xef, 0xc1, 0x57, 0x94, 0x95, 0xbc, 0x0a, 0xe6, 0x9c, 0x2d, 0xd2, 0x24, 0xe0, 0x25, 0x15,
	0x19, 0x27, 0x71, 0x50, 0x4e, 0x48, 0xb6, 0x5a, 0x92, 0x4d, 0xc1, 0x5f, 0x09, 0x2e, 0x39, 0x7a,
	0xaa, 0xd8, 0xbe, 0x66, 0xfb, 0x1b, 0xd0, 0xb0, 0x4f, 0x87, 0x09, 0xe7, 0x49, 0x46, 0x03, 0x45,
	0xbe, 0x29, 0x16, 0x01, 0x61, 0x95, 0x56, 0x9e, 0x3e, 0xdb, 0x86, 0xe2, 0x42, 0x10, 0x99, 0x72,
	0x66, 0xf0, 0x27, 0xdb, 0x78, 0x2e, 0x45, 0x31, 0x97, 0x06, 0x1d, 0x94, 0x24, 0x4b, 0x63, 0x22,
	0x69, 0xd0, 0xfc, 0x68, 0xc0, 0xfb, 0x05, 0x60, 0x37, 0xa4, 0x39, 0x2f, 0xc4, 0x9c, 0x5e, 0x70,
	0x96, 0x4a, 0x2e, 0xd0, 0x63, 0x78, 0xc0, 0xc8, 0x2d, 0x75, 0xc1, 0x08, 0x8c, 0x4f, 0xf0, 0xf1,
	0x1a, 0x1f, 0x08, 0x7b, 0x04, 0x42, 0x55, 0x44, 0x6f, 0xe0, 0x91, 0x4e, 0xef, 0xda, 0x23, 0x30,
	0x76, 0x26, 0x03, 0x5f, 0x37, 0xf6, 0x9b, 0xc6, 0xfe, 0x17, 0xd5, 0x18, 0xdb, 0x2e, 0x98, 0x59,
	0xa1, 0x21, 0xa3, 0xb7, 0xf0, 0x81, 0xac, 0x56, 0x34, 0x8e, 0x8c, 0xb8, 0xa5, 0xc4, 0xfd, 0x7b,
	0xe2, 0x29, 0xab, 0x66, 0x56, 0xe8, 0x28, 0xee, 0x07, 0x45, 0xc5, 0x1d, 0xe8, 0x68, 0x51, 0x54,
	0x57, 0xbd, 0x29, 0xec, 0x5d, 0x2f, 0x05, 0xcd, 0x97, 0x3c, 0x8b, 0xaf, 0x45, 0x9a, 0x24, 0x54,
	0xa0, 0x33, 0x78, 0x58, 0x92, 0xac, 0xd0, 0x91, 0x01, 0x1e, 0xac, 0x71, 0x1f, 0xa1, 0xa1, 0xa5,
	0xbe, 0xdf, 0xef, 0x5f, 0x58, 0xe6, 0x0b, 0x35, 0xcb, 0xfb, 0x01, 0xe0, 0x71, 0x23, 0xdd, 0xf9,
	0xd8, 0x4b, 0x78, 0x22, 0x9b, 0x5e, 0xe6, 0xbd, 0x81, 0xbf, 0x73, 0x85, 0xfe, 0x76, 0xb6, 0x99,
	0x15, 0xfe, 0xf3, 0xc0, 0x7d, 0xd8, 0x91, 0xba, 0x1e, 0x71, 0x46, 0xf9, 0x02, 0xb5, 0xfe, 0x60,
	0xe0, 0x7d, 0x83, 0x0f, 0x2f, 0x8d, 0xcf, 0x74, 0x5e, 0xef, 0x74, 0x77, 0xaa, 0xcf, 0xb0, 0x6d,
	0x4c, 0x72, 0xd7, 0x1e, 0xb5, 0xc6, 0xce, 0xe4, 0xf9, 0xbe, 0x50, 0x9a, 0x8e, 0xdb, 0x6b, 0x7c,
	0xf8, 0x13, 0xd8, 0x6d, 0x10, 0x6e, 0x1c, 0xbc, 0xef, 0x36, 0xec, 0x36, 0xdd, 0x2f, 0x08, 0x23,
	0xf5, 0x50, 0xce, 0x61, 0x4f, 0xd0, 0x45, 0x1d, 0x3a, 0x4a, 0x99, 0xa4, 0xa2, 0x24, 0x99, 0x8a,
	0xe2, 0x4c, 0x86, 0xf7, 0x36, 0x76, 0x6e, 0xee, 0x30, 0xec, 0x1a, 0xc9, 0x27, 0xa3, 0x40, 0x14,
	0x3e, 0x12, 0xe6, 0xb4, 0xa2, 0x5b, 0x7d, 0x5b, 0x4d, 0x60, 0x7f, 0x4f, 0xe0, 0xad, 0x93, 0xfc,
	0x2f, 0x78, 0x4f, 0xdc, 0x85, 0x72, 0xf4, 0x11, 0x1e, 0x13, 0x35, 0xb5, 0xdc, 0x6d, 0x29, 0xf3,
	0xb3, 0x3d, 0xe6, 0x77, 0x67, 0x1d, 0x36, 0x6a, 0xfc, 0x0e, 0xbe, 0x4c, 0xb9, 0xd6, 0xae, 0x04,
	0xff, 0x5a, 0xed, 0xb6, 0xc1, 0x9d, 0xc6, 0xe7, 0xaa, 0x1e, 0xc5, 0x15, 0xb8, 0x39, 0x52, 0x33,
	0x79, 0xfd, 0x37, 0x00, 0x00, 0xff, 0xff, 0x17, 0xd8, 0x65, 0x49, 0x13, 0x04, 0x00, 0x00,
}