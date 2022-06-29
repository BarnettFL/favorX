// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: multicast.proto

package pb

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type GIDs struct {
	Gid [][]byte `protobuf:"bytes,1,rep,name=gid,proto3" json:"gid,omitempty"`
}

func (m *GIDs) Reset()         { *m = GIDs{} }
func (m *GIDs) String() string { return proto.CompactTextString(m) }
func (*GIDs) ProtoMessage()    {}
func (*GIDs) Descriptor() ([]byte, []int) {
	return fileDescriptor_eedbde62517e047e, []int{0}
}
func (m *GIDs) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *GIDs) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_GIDs.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *GIDs) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GIDs.Merge(m, src)
}
func (m *GIDs) XXX_Size() int {
	return m.Size()
}
func (m *GIDs) XXX_DiscardUnknown() {
	xxx_messageInfo_GIDs.DiscardUnknown(m)
}

var xxx_messageInfo_GIDs proto.InternalMessageInfo

func (m *GIDs) GetGid() [][]byte {
	if m != nil {
		return m.Gid
	}
	return nil
}

type FindGroupReq struct {
	Gid   []byte   `protobuf:"bytes,1,opt,name=gid,proto3" json:"gid,omitempty"`
	Limit int32    `protobuf:"varint,2,opt,name=limit,proto3" json:"limit,omitempty"`
	Ttl   int32    `protobuf:"varint,3,opt,name=ttl,proto3" json:"ttl,omitempty"`
	Paths [][]byte `protobuf:"bytes,4,rep,name=paths,proto3" json:"paths,omitempty"`
}

func (m *FindGroupReq) Reset()         { *m = FindGroupReq{} }
func (m *FindGroupReq) String() string { return proto.CompactTextString(m) }
func (*FindGroupReq) ProtoMessage()    {}
func (*FindGroupReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_eedbde62517e047e, []int{1}
}
func (m *FindGroupReq) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *FindGroupReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_FindGroupReq.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *FindGroupReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FindGroupReq.Merge(m, src)
}
func (m *FindGroupReq) XXX_Size() int {
	return m.Size()
}
func (m *FindGroupReq) XXX_DiscardUnknown() {
	xxx_messageInfo_FindGroupReq.DiscardUnknown(m)
}

var xxx_messageInfo_FindGroupReq proto.InternalMessageInfo

func (m *FindGroupReq) GetGid() []byte {
	if m != nil {
		return m.Gid
	}
	return nil
}

func (m *FindGroupReq) GetLimit() int32 {
	if m != nil {
		return m.Limit
	}
	return 0
}

func (m *FindGroupReq) GetTtl() int32 {
	if m != nil {
		return m.Ttl
	}
	return 0
}

func (m *FindGroupReq) GetPaths() [][]byte {
	if m != nil {
		return m.Paths
	}
	return nil
}

type FindGroupResp struct {
	Addresses [][]byte `protobuf:"bytes,1,rep,name=addresses,proto3" json:"addresses,omitempty"`
}

func (m *FindGroupResp) Reset()         { *m = FindGroupResp{} }
func (m *FindGroupResp) String() string { return proto.CompactTextString(m) }
func (*FindGroupResp) ProtoMessage()    {}
func (*FindGroupResp) Descriptor() ([]byte, []int) {
	return fileDescriptor_eedbde62517e047e, []int{2}
}
func (m *FindGroupResp) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *FindGroupResp) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_FindGroupResp.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *FindGroupResp) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FindGroupResp.Merge(m, src)
}
func (m *FindGroupResp) XXX_Size() int {
	return m.Size()
}
func (m *FindGroupResp) XXX_DiscardUnknown() {
	xxx_messageInfo_FindGroupResp.DiscardUnknown(m)
}

var xxx_messageInfo_FindGroupResp proto.InternalMessageInfo

func (m *FindGroupResp) GetAddresses() [][]byte {
	if m != nil {
		return m.Addresses
	}
	return nil
}

type MulticastMsg struct {
	Id         uint64 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	CreateTime int64  `protobuf:"varint,2,opt,name=createTime,proto3" json:"createTime,omitempty"`
	Origin     []byte `protobuf:"bytes,3,opt,name=origin,proto3" json:"origin,omitempty"`
	Gid        []byte `protobuf:"bytes,4,opt,name=gid,proto3" json:"gid,omitempty"`
	Data       []byte `protobuf:"bytes,5,opt,name=data,proto3" json:"data,omitempty"`
}

func (m *MulticastMsg) Reset()         { *m = MulticastMsg{} }
func (m *MulticastMsg) String() string { return proto.CompactTextString(m) }
func (*MulticastMsg) ProtoMessage()    {}
func (*MulticastMsg) Descriptor() ([]byte, []int) {
	return fileDescriptor_eedbde62517e047e, []int{3}
}
func (m *MulticastMsg) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *MulticastMsg) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_MulticastMsg.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *MulticastMsg) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MulticastMsg.Merge(m, src)
}
func (m *MulticastMsg) XXX_Size() int {
	return m.Size()
}
func (m *MulticastMsg) XXX_DiscardUnknown() {
	xxx_messageInfo_MulticastMsg.DiscardUnknown(m)
}

var xxx_messageInfo_MulticastMsg proto.InternalMessageInfo

func (m *MulticastMsg) GetId() uint64 {
	if m != nil {
		return m.Id
	}
	return 0
}

func (m *MulticastMsg) GetCreateTime() int64 {
	if m != nil {
		return m.CreateTime
	}
	return 0
}

func (m *MulticastMsg) GetOrigin() []byte {
	if m != nil {
		return m.Origin
	}
	return nil
}

func (m *MulticastMsg) GetGid() []byte {
	if m != nil {
		return m.Gid
	}
	return nil
}

func (m *MulticastMsg) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

type Notify struct {
	Status int32    `protobuf:"varint,1,opt,name=status,proto3" json:"status,omitempty"`
	Gids   [][]byte `protobuf:"bytes,2,rep,name=gids,proto3" json:"gids,omitempty"`
}

func (m *Notify) Reset()         { *m = Notify{} }
func (m *Notify) String() string { return proto.CompactTextString(m) }
func (*Notify) ProtoMessage()    {}
func (*Notify) Descriptor() ([]byte, []int) {
	return fileDescriptor_eedbde62517e047e, []int{4}
}
func (m *Notify) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Notify) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Notify.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Notify) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Notify.Merge(m, src)
}
func (m *Notify) XXX_Size() int {
	return m.Size()
}
func (m *Notify) XXX_DiscardUnknown() {
	xxx_messageInfo_Notify.DiscardUnknown(m)
}

var xxx_messageInfo_Notify proto.InternalMessageInfo

func (m *Notify) GetStatus() int32 {
	if m != nil {
		return m.Status
	}
	return 0
}

func (m *Notify) GetGids() [][]byte {
	if m != nil {
		return m.Gids
	}
	return nil
}

type GroupMsg struct {
	Gid  []byte `protobuf:"bytes,1,opt,name=gid,proto3" json:"gid,omitempty"`
	Data []byte `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	Type int32  `protobuf:"varint,3,opt,name=type,proto3" json:"type,omitempty"`
	Err  string `protobuf:"bytes,4,opt,name=err,proto3" json:"err,omitempty"`
}

func (m *GroupMsg) Reset()         { *m = GroupMsg{} }
func (m *GroupMsg) String() string { return proto.CompactTextString(m) }
func (*GroupMsg) ProtoMessage()    {}
func (*GroupMsg) Descriptor() ([]byte, []int) {
	return fileDescriptor_eedbde62517e047e, []int{5}
}
func (m *GroupMsg) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *GroupMsg) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_GroupMsg.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *GroupMsg) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GroupMsg.Merge(m, src)
}
func (m *GroupMsg) XXX_Size() int {
	return m.Size()
}
func (m *GroupMsg) XXX_DiscardUnknown() {
	xxx_messageInfo_GroupMsg.DiscardUnknown(m)
}

var xxx_messageInfo_GroupMsg proto.InternalMessageInfo

func (m *GroupMsg) GetGid() []byte {
	if m != nil {
		return m.Gid
	}
	return nil
}

func (m *GroupMsg) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *GroupMsg) GetType() int32 {
	if m != nil {
		return m.Type
	}
	return 0
}

func (m *GroupMsg) GetErr() string {
	if m != nil {
		return m.Err
	}
	return ""
}

func init() {
	proto.RegisterType((*GIDs)(nil), "multicastFavorX.GIDs")
	proto.RegisterType((*FindGroupReq)(nil), "multicastFavorX.FindGroupReq")
	proto.RegisterType((*FindGroupResp)(nil), "multicastFavorX.FindGroupResp")
	proto.RegisterType((*MulticastMsg)(nil), "multicastFavorX.MulticastMsg")
	proto.RegisterType((*Notify)(nil), "multicastFavorX.Notify")
	proto.RegisterType((*GroupMsg)(nil), "multicastFavorX.GroupMsg")
}

func init() { proto.RegisterFile("multicast.proto", fileDescriptor_eedbde62517e047e) }

var fileDescriptor_eedbde62517e047e = []byte{
	// 332 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x64, 0x91, 0x4f, 0x4b, 0x33, 0x31,
	0x10, 0xc6, 0xbb, 0xff, 0xca, 0xdb, 0x61, 0xdf, 0x3f, 0x84, 0x17, 0xc9, 0xa1, 0x84, 0xb2, 0xa7,
	0x5e, 0xf4, 0xa2, 0x9f, 0x40, 0xa4, 0xc5, 0x43, 0x3d, 0x04, 0x11, 0xf1, 0x20, 0xa4, 0x4d, 0x5c,
	0x03, 0x6d, 0x77, 0x4d, 0xa6, 0x42, 0xc1, 0x0f, 0xe1, 0xc7, 0xf2, 0xd8, 0xa3, 0x47, 0x69, 0xbf,
	0x88, 0x64, 0xba, 0x65, 0x0b, 0xde, 0x9e, 0x79, 0x78, 0x32, 0xf3, 0x9b, 0x09, 0xfc, 0x5d, 0xac,
	0xe6, 0x68, 0x67, 0xca, 0xe3, 0x59, 0xed, 0x2a, 0xac, 0x58, 0x6b, 0x8c, 0xd4, 0x6b, 0xe5, 0xee,
	0x0b, 0x0e, 0xe9, 0xf8, 0xfa, 0xca, 0xb3, 0x7f, 0x90, 0x94, 0x56, 0xf3, 0x68, 0x90, 0x0c, 0x73,
	0x19, 0x64, 0xf1, 0x08, 0xf9, 0xc8, 0x2e, 0xf5, 0xd8, 0x55, 0xab, 0x5a, 0x9a, 0x97, 0x36, 0x11,
	0x35, 0x09, 0xf6, 0x1f, 0xb2, 0xb9, 0x5d, 0x58, 0xe4, 0xf1, 0x20, 0x1a, 0x66, 0x72, 0x5f, 0x84,
	0x1c, 0xe2, 0x9c, 0x27, 0xe4, 0x05, 0x19, 0x72, 0xb5, 0xc2, 0x67, 0xcf, 0x53, 0xea, 0xbe, 0x2f,
	0x8a, 0x53, 0xf8, 0x7d, 0xd4, 0xdf, 0xd7, 0xac, 0x0f, 0x3d, 0xa5, 0xb5, 0x33, 0xde, 0x1b, 0xdf,
	0x80, 0xb4, 0x46, 0xf1, 0x06, 0xf9, 0xe4, 0xc0, 0x3e, 0xf1, 0x25, 0xfb, 0x03, 0x71, 0x43, 0x93,
	0xca, 0xd8, 0x6a, 0x26, 0x00, 0x66, 0xce, 0x28, 0x34, 0xb7, 0x76, 0x61, 0x88, 0x28, 0x91, 0x47,
	0x0e, 0x3b, 0x81, 0x6e, 0xe5, 0x6c, 0x69, 0x97, 0x44, 0x96, 0xcb, 0xa6, 0x3a, 0xac, 0x95, 0xb6,
	0x6b, 0x31, 0x48, 0xb5, 0x42, 0xc5, 0x33, 0xb2, 0x48, 0x17, 0x17, 0xd0, 0xbd, 0xa9, 0xd0, 0x3e,
	0xad, 0x43, 0x1f, 0x8f, 0x0a, 0x57, 0x9e, 0x66, 0x67, 0xb2, 0xa9, 0xc2, 0xab, 0xd2, 0x6a, 0xcf,
	0x63, 0x02, 0x27, 0x5d, 0xdc, 0xc1, 0x2f, 0x5a, 0x2f, 0xf0, 0xfe, 0x3c, 0xdf, 0x61, 0x4e, 0xdc,
	0xce, 0x09, 0x1e, 0xae, 0x6b, 0xd3, 0x5c, 0x8f, 0x74, 0x78, 0x69, 0x9c, 0x23, 0xc2, 0x9e, 0x0c,
	0xf2, 0xb2, 0xff, 0xb1, 0x15, 0xd1, 0x66, 0x2b, 0xa2, 0xaf, 0xad, 0x88, 0xde, 0x77, 0xa2, 0xb3,
	0xd9, 0x89, 0xce, 0xe7, 0x4e, 0x74, 0x1e, 0xe2, 0x7a, 0x3a, 0xed, 0xd2, 0x57, 0x9f, 0x7f, 0x07,
	0x00, 0x00, 0xff, 0xff, 0x7f, 0x0b, 0x05, 0xd0, 0xfd, 0x01, 0x00, 0x00,
}

func (m *GIDs) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GIDs) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *GIDs) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Gid) > 0 {
		for iNdEx := len(m.Gid) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Gid[iNdEx])
			copy(dAtA[i:], m.Gid[iNdEx])
			i = encodeVarintMulticast(dAtA, i, uint64(len(m.Gid[iNdEx])))
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func (m *FindGroupReq) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *FindGroupReq) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *FindGroupReq) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Paths) > 0 {
		for iNdEx := len(m.Paths) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Paths[iNdEx])
			copy(dAtA[i:], m.Paths[iNdEx])
			i = encodeVarintMulticast(dAtA, i, uint64(len(m.Paths[iNdEx])))
			i--
			dAtA[i] = 0x22
		}
	}
	if m.Ttl != 0 {
		i = encodeVarintMulticast(dAtA, i, uint64(m.Ttl))
		i--
		dAtA[i] = 0x18
	}
	if m.Limit != 0 {
		i = encodeVarintMulticast(dAtA, i, uint64(m.Limit))
		i--
		dAtA[i] = 0x10
	}
	if len(m.Gid) > 0 {
		i -= len(m.Gid)
		copy(dAtA[i:], m.Gid)
		i = encodeVarintMulticast(dAtA, i, uint64(len(m.Gid)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *FindGroupResp) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *FindGroupResp) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *FindGroupResp) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Addresses) > 0 {
		for iNdEx := len(m.Addresses) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Addresses[iNdEx])
			copy(dAtA[i:], m.Addresses[iNdEx])
			i = encodeVarintMulticast(dAtA, i, uint64(len(m.Addresses[iNdEx])))
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func (m *MulticastMsg) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *MulticastMsg) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *MulticastMsg) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Data) > 0 {
		i -= len(m.Data)
		copy(dAtA[i:], m.Data)
		i = encodeVarintMulticast(dAtA, i, uint64(len(m.Data)))
		i--
		dAtA[i] = 0x2a
	}
	if len(m.Gid) > 0 {
		i -= len(m.Gid)
		copy(dAtA[i:], m.Gid)
		i = encodeVarintMulticast(dAtA, i, uint64(len(m.Gid)))
		i--
		dAtA[i] = 0x22
	}
	if len(m.Origin) > 0 {
		i -= len(m.Origin)
		copy(dAtA[i:], m.Origin)
		i = encodeVarintMulticast(dAtA, i, uint64(len(m.Origin)))
		i--
		dAtA[i] = 0x1a
	}
	if m.CreateTime != 0 {
		i = encodeVarintMulticast(dAtA, i, uint64(m.CreateTime))
		i--
		dAtA[i] = 0x10
	}
	if m.Id != 0 {
		i = encodeVarintMulticast(dAtA, i, uint64(m.Id))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *Notify) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Notify) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Notify) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Gids) > 0 {
		for iNdEx := len(m.Gids) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Gids[iNdEx])
			copy(dAtA[i:], m.Gids[iNdEx])
			i = encodeVarintMulticast(dAtA, i, uint64(len(m.Gids[iNdEx])))
			i--
			dAtA[i] = 0x12
		}
	}
	if m.Status != 0 {
		i = encodeVarintMulticast(dAtA, i, uint64(m.Status))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *GroupMsg) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GroupMsg) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *GroupMsg) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Err) > 0 {
		i -= len(m.Err)
		copy(dAtA[i:], m.Err)
		i = encodeVarintMulticast(dAtA, i, uint64(len(m.Err)))
		i--
		dAtA[i] = 0x22
	}
	if m.Type != 0 {
		i = encodeVarintMulticast(dAtA, i, uint64(m.Type))
		i--
		dAtA[i] = 0x18
	}
	if len(m.Data) > 0 {
		i -= len(m.Data)
		copy(dAtA[i:], m.Data)
		i = encodeVarintMulticast(dAtA, i, uint64(len(m.Data)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Gid) > 0 {
		i -= len(m.Gid)
		copy(dAtA[i:], m.Gid)
		i = encodeVarintMulticast(dAtA, i, uint64(len(m.Gid)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintMulticast(dAtA []byte, offset int, v uint64) int {
	offset -= sovMulticast(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *GIDs) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Gid) > 0 {
		for _, b := range m.Gid {
			l = len(b)
			n += 1 + l + sovMulticast(uint64(l))
		}
	}
	return n
}

func (m *FindGroupReq) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Gid)
	if l > 0 {
		n += 1 + l + sovMulticast(uint64(l))
	}
	if m.Limit != 0 {
		n += 1 + sovMulticast(uint64(m.Limit))
	}
	if m.Ttl != 0 {
		n += 1 + sovMulticast(uint64(m.Ttl))
	}
	if len(m.Paths) > 0 {
		for _, b := range m.Paths {
			l = len(b)
			n += 1 + l + sovMulticast(uint64(l))
		}
	}
	return n
}

func (m *FindGroupResp) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Addresses) > 0 {
		for _, b := range m.Addresses {
			l = len(b)
			n += 1 + l + sovMulticast(uint64(l))
		}
	}
	return n
}

func (m *MulticastMsg) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Id != 0 {
		n += 1 + sovMulticast(uint64(m.Id))
	}
	if m.CreateTime != 0 {
		n += 1 + sovMulticast(uint64(m.CreateTime))
	}
	l = len(m.Origin)
	if l > 0 {
		n += 1 + l + sovMulticast(uint64(l))
	}
	l = len(m.Gid)
	if l > 0 {
		n += 1 + l + sovMulticast(uint64(l))
	}
	l = len(m.Data)
	if l > 0 {
		n += 1 + l + sovMulticast(uint64(l))
	}
	return n
}

func (m *Notify) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Status != 0 {
		n += 1 + sovMulticast(uint64(m.Status))
	}
	if len(m.Gids) > 0 {
		for _, b := range m.Gids {
			l = len(b)
			n += 1 + l + sovMulticast(uint64(l))
		}
	}
	return n
}

func (m *GroupMsg) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Gid)
	if l > 0 {
		n += 1 + l + sovMulticast(uint64(l))
	}
	l = len(m.Data)
	if l > 0 {
		n += 1 + l + sovMulticast(uint64(l))
	}
	if m.Type != 0 {
		n += 1 + sovMulticast(uint64(m.Type))
	}
	l = len(m.Err)
	if l > 0 {
		n += 1 + l + sovMulticast(uint64(l))
	}
	return n
}

func sovMulticast(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozMulticast(x uint64) (n int) {
	return sovMulticast(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *GIDs) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMulticast
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: GIDs: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GIDs: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Gid", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMulticast
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMulticast
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Gid = append(m.Gid, make([]byte, postIndex-iNdEx))
			copy(m.Gid[len(m.Gid)-1], dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMulticast(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthMulticast
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *FindGroupReq) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMulticast
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: FindGroupReq: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: FindGroupReq: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Gid", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMulticast
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMulticast
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Gid = append(m.Gid[:0], dAtA[iNdEx:postIndex]...)
			if m.Gid == nil {
				m.Gid = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Limit", wireType)
			}
			m.Limit = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Limit |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Ttl", wireType)
			}
			m.Ttl = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Ttl |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Paths", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMulticast
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMulticast
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Paths = append(m.Paths, make([]byte, postIndex-iNdEx))
			copy(m.Paths[len(m.Paths)-1], dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMulticast(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthMulticast
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *FindGroupResp) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMulticast
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: FindGroupResp: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: FindGroupResp: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Addresses", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMulticast
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMulticast
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Addresses = append(m.Addresses, make([]byte, postIndex-iNdEx))
			copy(m.Addresses[len(m.Addresses)-1], dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMulticast(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthMulticast
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *MulticastMsg) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMulticast
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: MulticastMsg: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MulticastMsg: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
			}
			m.Id = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Id |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field CreateTime", wireType)
			}
			m.CreateTime = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.CreateTime |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Origin", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMulticast
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMulticast
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Origin = append(m.Origin[:0], dAtA[iNdEx:postIndex]...)
			if m.Origin == nil {
				m.Origin = []byte{}
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Gid", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMulticast
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMulticast
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Gid = append(m.Gid[:0], dAtA[iNdEx:postIndex]...)
			if m.Gid == nil {
				m.Gid = []byte{}
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Data", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMulticast
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMulticast
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Data = append(m.Data[:0], dAtA[iNdEx:postIndex]...)
			if m.Data == nil {
				m.Data = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMulticast(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthMulticast
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Notify) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMulticast
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Notify: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Notify: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Status", wireType)
			}
			m.Status = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Status |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Gids", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMulticast
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMulticast
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Gids = append(m.Gids, make([]byte, postIndex-iNdEx))
			copy(m.Gids[len(m.Gids)-1], dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMulticast(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthMulticast
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *GroupMsg) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMulticast
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: GroupMsg: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GroupMsg: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Gid", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMulticast
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMulticast
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Gid = append(m.Gid[:0], dAtA[iNdEx:postIndex]...)
			if m.Gid == nil {
				m.Gid = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Data", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMulticast
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMulticast
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Data = append(m.Data[:0], dAtA[iNdEx:postIndex]...)
			if m.Data == nil {
				m.Data = []byte{}
			}
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			m.Type = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Type |= int32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Err", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthMulticast
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMulticast
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Err = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMulticast(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthMulticast
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipMulticast(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowMulticast
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMulticast
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthMulticast
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupMulticast
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthMulticast
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthMulticast        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowMulticast          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupMulticast = fmt.Errorf("proto: unexpected end of group")
)
