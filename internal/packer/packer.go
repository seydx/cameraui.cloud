package packer

import (
	"github.com/vmihailenco/msgpack/v5"
)

func PackMessage(data any) ([]byte, error) {
	return msgpack.Marshal(data)
}

func UnpackMessage(data []byte, v any) error {
	return msgpack.Unmarshal(data, v)
}
