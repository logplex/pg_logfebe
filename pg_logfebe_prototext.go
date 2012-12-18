package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
)

type Message struct {
	typ  byte
	data []byte
}

type Version struct {
	*Message
	Version string
}

func NewVersion(m *Message) (*Version, error) {
	var v Version
	if m.typ != 'V' {
		panic("Bad input to initVersion")
	}

	vBuf := bytes.NewBuffer(m.data)
	vStr, err := readCString(vBuf)
	if err != nil {
		return nil, err
	}

	if vBuf.Len() != 0 {
		return nil, fmt.Errorf("Version message has mismatched "+
			"length header and cString contents: remaining %d",
			vBuf.Len())
	}

	v.Version = vStr
	v.Message = m

	return &v, nil
}

type Identification struct {
	*Message
	Ident string
}

func NewIdentification(m *Message) (*Identification, error) {
	var ident Identification

	if m.typ != 'I' {
		panic("Bad input to initIdentification")
	}

	iBuf := bytes.NewBuffer(m.data)
	iStr, err := readCString(iBuf)
	if err != nil {
		return nil, err
	}

	ident.Ident = iStr
	ident.Message = m

	return &ident, nil
}

type LogRecord struct {
	*Message

	LogTime          string
	UserName         *string
	DatabaseName     *string
	Pid              int32
	ClientAddr       *string
	SessionId        string
	SeqNum           int64
	PsDisplay        *string
	SessionStart     string
	Vxid             *string
	Txid             uint64
	ELevel           int32
	SQLState         *string
	ErrMessage       *string
	ErrDetail        *string
	ErrHint          *string
	InternalQuery    *string
	InternalQueryPos int32
	ErrContext       *string
	UserQuery        *string
	UserQueryPos     int32
	FileErrPos       *string
	ApplicationName  *string
}

func (lr *LogRecord) oneLine() []byte {
	buf := bytes.Buffer{}

	wd := func() {
		buf.WriteByte(' ')
	}

	ws := func(name string, s string) {
		buf.WriteString(fmt.Sprintf("%s=%q", name, s))
	}

	wns := func(name string, s *string) {
		body := func() string {
			if s == nil {
				return "NULL"
			} else {
				return fmt.Sprintf("[%q]", *s)
			}
		}()

		buf.WriteString(name)
		buf.WriteByte('=')
		buf.WriteString(body)
	}

	wnum := func(name string, n interface{}) {
		buf.WriteString(fmt.Sprintf("%s=%v", name, n))
	}

	ws("LogTime", lr.LogTime)
	wd()
	wns("UserName", lr.UserName)
	wd()
	wns("DatabaseName", lr.DatabaseName)
	wd()
	wnum("Pid", lr.Pid)
	wd()
	wns("ClientAddr", lr.ClientAddr)
	wd()
	ws("SessionId", lr.SessionId)
	wd()
	wnum("SeqNum", lr.SeqNum)
	wd()
	wns("PsDisplay", lr.PsDisplay)
	wd()
	ws("SessionStart", lr.SessionStart)
	wd()
	wns("Vxid", lr.Vxid)
	wd()
	wnum("Txid", lr.Txid)
	wd()
	wnum("ELevel", lr.ELevel)
	wd()
	wns("SQLState", lr.SQLState)
	wd()
	wns("ErrMessage", lr.ErrMessage)
	wd()
	wns("ErrDetail", lr.ErrDetail)
	wd()
	wns("ErrHint", lr.ErrHint)
	wd()
	wns("InternalQuery", lr.InternalQuery)
	wd()
	wnum("InternalQueryPos", lr.InternalQueryPos)
	wd()
	wns("ErrContext", lr.ErrContext)
	wd()
	wns("UserQuery", lr.UserQuery)
	wd()
	wnum("UserQueryPos", lr.UserQueryPos)
	wd()
	wns("FileErrPos", lr.FileErrPos)
	wd()
	wns("ApplicationName", lr.ApplicationName)

	return buf.Bytes()
}

func NewLogRecord(m *Message) (lrp *LogRecord, err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}

			err = r.(error)
		}
	}()

	buf := bytes.NewBuffer(m.data)

	// Read the next nullable string from buf, returning a 'nil'
	// *string should it be null.
	nextNullableString := func() *string {
		np, _ := readByte(buf)

		switch np {
		case 'P':
			s, err := readCString(buf)
			if err != nil {
				panic(err)
			}

			return &s

		case 'N':
			// 'N' is still followed by a NUL byte that
			// must be consumed.
			_, err := readCString(buf)
			if err != nil {
				panic(err)
			}

			return nil

		default:
			panic(fmt.Errorf("Expected nullable string "+
				"control character, got %c", np))

		}

		panic("Prior switch should always return")
	}

	// Read a non-nullable string from buf
	nextString := func() string {
		s, err := readCString(buf)
		if err != nil {
			panic(err)
		}

		return s
	}

	nextInt32 := func() int32 {
		i32, err := readInt32(buf)
		if err != nil {
			panic(err)
		}

		return i32
	}

	nextInt64 := func() int64 {
		i64, err := readInt64(buf)
		if err != nil {
			panic(err)
		}

		return i64
	}

	nextUint64 := func() uint64 {
		ui64, err := readUint64(buf)
		if err != nil {
			panic(err)
		}

		return ui64
	}

	lr := LogRecord{}

	lr.LogTime = nextString()
	lr.UserName = nextNullableString()
	lr.DatabaseName = nextNullableString()
	lr.Pid = nextInt32()
	lr.ClientAddr = nextNullableString()
	lr.SessionId = nextString()
	lr.SeqNum = nextInt64()
	lr.PsDisplay = nextNullableString()
	lr.SessionStart = nextString()
	lr.Vxid = nextNullableString()
	lr.Txid = nextUint64()
	lr.ELevel = nextInt32()
	lr.SQLState = nextNullableString()
	lr.ErrMessage = nextNullableString()
	lr.ErrDetail = nextNullableString()
	lr.ErrHint = nextNullableString()
	lr.InternalQuery = nextNullableString()
	lr.InternalQueryPos = nextInt32()
	lr.ErrContext = nextNullableString()
	lr.UserQuery = nextNullableString()
	lr.UserQueryPos = nextInt32()
	lr.FileErrPos = nextNullableString()
	lr.ApplicationName = nextNullableString()

	lr.Message = m

	if buf.Len() != 0 {
		return nil, fmt.Errorf("LogRecord message has mismatched "+
			"length header and cString contents: remaining %d",
			buf.Len())
	}

	return &lr, nil
}

func readMessage(r io.Reader, assertType byte) (*Message, error) {
	msgType, err := readByte(r)
	if err != nil {
		return nil, err
	}

	if msgType != assertType {
		return nil, fmt.Errorf(
			"Unexpected message type: expected %c, recevied %c",
			assertType, msgType)
	}

	length, err := readInt32(r)
	if err != nil {
		return nil, err
	} else if length < 0 {
		return nil, fmt.Errorf(
			"Expected a positive value for length, got %d", length)
	}

	payloadLen := length - 4
	msg := Message{
		typ:  msgType,
		data: make([]byte, payloadLen, payloadLen),
	}

	// Read payload
	if _, err := io.ReadFull(r, msg.data); err != nil {
		return nil, err
	}

	return &msg, nil
}

func handleConnection(cConn net.Conn) {
	r := bufio.NewReader(cConn)

	vMsg, err := readMessage(r, 'V')
	if err != nil {
		log.Println(err)
		return
	}

	version, err := NewVersion(vMsg)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println(version)

	// TODO: error check vMsg

	iMsg, err := readMessage(r, 'I')
	if err != nil {
		log.Println(err)
		return
	}

	ident, err := NewIdentification(iMsg)
	if err != nil {
		log.Println(err)
		return
	}

	// TODO: error check identity
	log.Printf("%#v\n", ident)

	for {
		lMsg, err := readMessage(r, 'L')
		if err != nil {
			log.Println(err)
			return
		}

		lr, err := NewLogRecord(lMsg)
		log.Printf("%#s\n", lMsg.data)
		if err != nil {
			log.Println(err)
			return
		}

		log.Println(string(lr.oneLine()))
	}
}

func main() {
	if len(os.Args) != 2 {
		log.Printf("Usage: pg_logfebe_prototext PATH\n")
		os.Exit(1)
	}

	ln, err := net.Listen("unix", os.Args[1])
	if err != nil {
		log.Printf("Could not listen on address: %v\n", err)
		os.Exit(1)
	}

	// Signal handling; this is pretty ghetto now, but at least we
	// can exit cleanly on an interrupt. N.B.: this currently does
	// not correctly capture SIGTERM on Linux (and possibly
	// elsewhere)--it just kills the process directly without
	// involving the signal handler.
	sigch := make(chan os.Signal)
	signal.Notify(sigch, os.Interrupt, os.Kill)
	watchSigs := func() {
		for sig := range sigch {
			log.Printf("Got signal %v", sig)
			if sig == os.Kill {
				os.Exit(2)
			} else if sig == os.Interrupt {
				os.Exit(0)
			}
		}
	}
	go watchSigs()

	for {
		conn, err := ln.Accept()

		if err != nil {
			log.Printf("Error: %v\n", err)
			continue
		}

		go handleConnection(conn)
	}

	log.Println("pg_logfebe_prototext.go quits successfully")
	return
}

// Low level data type reading functions follow

func readByte(r io.Reader) (ret byte, err error) {
	var be [1]byte
	valBytes := be[0:1]

	if _, err = io.ReadFull(r, valBytes); err != nil {
		return 0, err
	}

	return valBytes[0], nil
}

func readInt32(r io.Reader) (int32, error) {
	var be [4]byte
	valBytes := be[0:4]
	if _, err := io.ReadFull(r, valBytes); err != nil {
		return 0, err
	}

	return int32(binary.BigEndian.Uint32(valBytes)), nil
}

// ReadCString reads a null-terminated string in UTF-8 encoding from
// the io.Reader r. If an error is encountered in decoding, it returns
// an empty string and the error.
func readCString(r io.Reader) (s string, err error) {
	var be [1]byte
	charBuf := be[0:1]

	var accum bytes.Buffer

	for {
		n, err := r.Read(charBuf)

		if err != nil {
			return "", err
		}

		// Handle the case of no error, yet no bytes were
		// retrieved.
		if n < 1 {
			continue
		}

		switch charBuf[0] {
		case '\000':
			return string(accum.Bytes()), nil
		default:
			accum.Write(charBuf)
		}
	}

	panic("Oh snap")
}

func readInt64(r io.Reader) (ret int64, err error) {
	var be [8]byte

	valBytes := be[0:8]
	if _, err = io.ReadFull(r, valBytes); err != nil {
		return 0, err
	}

	return int64(binary.BigEndian.Uint64(valBytes)), nil
}

func readUint64(r io.Reader) (ret uint64, err error) {
	var be [8]byte

	valBytes := be[0:8]
	if _, err = io.ReadFull(r, valBytes); err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint64(valBytes), nil
}
