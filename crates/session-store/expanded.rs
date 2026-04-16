#![feature(prelude_import)]
#[macro_use]
extern crate std;
#[prelude_import]
use std::prelude::rust_2024::*;
mod cipher {
    pub trait Cipher {
        fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError>;
        fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError>;
    }
    pub enum CipherError {
        Encrypt(String),
        Decrypt(String),
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for CipherError {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                CipherError::Encrypt(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Encrypt",
                        &__self_0,
                    )
                }
                CipherError::Decrypt(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Decrypt",
                        &__self_0,
                    )
                }
            }
        }
    }
    impl std::fmt::Display for CipherError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Encrypt(e) => f.write_fmt(format_args!("encrypt error: {0}", e)),
                Self::Decrypt(e) => f.write_fmt(format_args!("decrypt error: {0}", e)),
            }
        }
    }
    impl std::error::Error for CipherError {}
    /// No-op cipher for development/testing.
    pub struct NoCipher;
    impl Cipher for NoCipher {
        fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
            Ok(plaintext.to_vec())
        }
        fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
            Ok(ciphertext.to_vec())
        }
    }
}
mod encrypted {
    use crate::cipher::Cipher;
    use crate::error::StoreError;
    use crate::store::Store;
    pub struct EncryptedStore<S: Store<Vec<u8>>, C: Cipher> {
        inner: S,
        cipher: C,
    }
    impl<S: Store<Vec<u8>>, C: Cipher> EncryptedStore<S, C> {
        pub fn new(inner: S, cipher: C) -> Self {
            Self { inner, cipher }
        }
    }
    impl<S: Store<Vec<u8>> + Send, C: Cipher + Send> Store<Vec<u8>>
    for EncryptedStore<S, C> {
        async fn put(&mut self, key: &str, value: &Vec<u8>) -> Result<(), StoreError> {
            let encrypted = self.cipher.encrypt(value).map_err(StoreError::Cipher)?;
            self.inner.put(key, &encrypted).await
        }
        async fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
            match self.inner.get(key).await? {
                None => Ok(None),
                Some(encrypted) => {
                    let decrypted = self
                        .cipher
                        .decrypt(&encrypted)
                        .map_err(StoreError::Cipher)?;
                    Ok(Some(decrypted))
                }
            }
        }
        async fn delete(&mut self, key: &str) -> Result<(), StoreError> {
            self.inner.delete(key).await
        }
    }
}
mod error {
    use crate::cipher::CipherError;
    pub enum StoreError {
        Transport(String),
        Serialize(rmp_serde::encode::Error),
        Deserialize(rmp_serde::decode::Error),
        Cipher(CipherError),
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for StoreError {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                StoreError::Transport(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Transport",
                        &__self_0,
                    )
                }
                StoreError::Serialize(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Serialize",
                        &__self_0,
                    )
                }
                StoreError::Deserialize(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Deserialize",
                        &__self_0,
                    )
                }
                StoreError::Cipher(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Cipher",
                        &__self_0,
                    )
                }
            }
        }
    }
    impl std::fmt::Display for StoreError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Transport(e) => f.write_fmt(format_args!("transport: {0}", e)),
                Self::Serialize(e) => f.write_fmt(format_args!("serialize: {0}", e)),
                Self::Deserialize(e) => f.write_fmt(format_args!("deserialize: {0}", e)),
                Self::Cipher(e) => f.write_fmt(format_args!("cipher: {0}", e)),
            }
        }
    }
    impl std::error::Error for StoreError {}
}
mod grpc {
    use tonic::transport::Channel;
    use crate::error::StoreError;
    use crate::proto::blob_store_client::BlobStoreClient;
    use crate::proto::{DeleteRequest, GetRequest, PutRequest};
    use crate::store::Store;
    pub struct GrpcStore {
        client: BlobStoreClient<Channel>,
        prefix: String,
    }
    impl GrpcStore {
        pub async fn connect_uds(
            socket_path: &str,
            prefix: &str,
        ) -> Result<Self, StoreError> {
            let uri = ::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!("unix://{0}", socket_path))
            });
            let client = BlobStoreClient::connect(uri)
                .await
                .map_err(|e| StoreError::Transport(e.to_string()))?;
            Ok(Self {
                client,
                prefix: prefix.to_string(),
            })
        }
        fn prefixed_key(&self, key: &str) -> String {
            ::alloc::__export::must_use({
                ::alloc::fmt::format(format_args!("{0}:{1}", self.prefix, key))
            })
        }
    }
    impl Store<Vec<u8>> for GrpcStore {
        async fn put(&mut self, key: &str, value: &Vec<u8>) -> Result<(), StoreError> {
            self.client
                .put(PutRequest {
                    key: self.prefixed_key(key),
                    data: value.clone(),
                })
                .await
                .map_err(|e| StoreError::Transport(e.to_string()))?;
            Ok(())
        }
        async fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
            let response = self
                .client
                .get(GetRequest {
                    key: self.prefixed_key(key),
                })
                .await
                .map_err(|e| StoreError::Transport(e.to_string()))?;
            Ok(response.into_inner().data)
        }
        async fn delete(&mut self, key: &str) -> Result<(), StoreError> {
            self.client
                .delete(DeleteRequest {
                    key: self.prefixed_key(key),
                })
                .await
                .map_err(|e| StoreError::Transport(e.to_string()))?;
            Ok(())
        }
    }
}
mod serde {
    use std::marker::PhantomData;
    use serde::{de::DeserializeOwned, Serialize};
    use crate::error::StoreError;
    use crate::store::Store;
    pub struct SerdeStore<S: Store<Vec<u8>>, T> {
        inner: S,
        _phantom: PhantomData<T>,
    }
    impl<S: Store<Vec<u8>>, T> SerdeStore<S, T> {
        pub fn new(inner: S) -> Self {
            Self {
                inner,
                _phantom: PhantomData,
            }
        }
    }
    impl<
        S: Store<Vec<u8>> + Send,
        T: Serialize + DeserializeOwned + Send + Sync,
    > Store<T> for SerdeStore<S, T> {
        async fn put(&mut self, key: &str, value: &T) -> Result<(), StoreError> {
            let bytes = rmp_serde::to_vec(value).map_err(StoreError::Serialize)?;
            self.inner.put(key, &bytes).await
        }
        async fn get(&mut self, key: &str) -> Result<Option<T>, StoreError> {
            match self.inner.get(key).await? {
                None => Ok(None),
                Some(bytes) => {
                    let value = rmp_serde::from_slice(&bytes)
                        .map_err(StoreError::Deserialize)?;
                    Ok(Some(value))
                }
            }
        }
        async fn delete(&mut self, key: &str) -> Result<(), StoreError> {
            self.inner.delete(key).await
        }
    }
}
mod store {
    use crate::error::StoreError;
    /// Generic async store trait parameterized by value type.
    pub trait Store<V>: Send {
        fn put(
            &mut self,
            key: &str,
            value: &V,
        ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send;
        fn get(
            &mut self,
            key: &str,
        ) -> impl std::future::Future<Output = Result<Option<V>, StoreError>> + Send;
        fn delete(
            &mut self,
            key: &str,
        ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send;
    }
}
mod proto {
    pub struct PutRequest {
        #[prost(string, tag = "1")]
        pub key: ::prost::alloc::string::String,
        #[prost(bytes = "vec", tag = "2")]
        pub data: ::prost::alloc::vec::Vec<u8>,
    }
    #[automatically_derived]
    impl ::core::clone::Clone for PutRequest {
        #[inline]
        fn clone(&self) -> PutRequest {
            PutRequest {
                key: ::core::clone::Clone::clone(&self.key),
                data: ::core::clone::Clone::clone(&self.data),
            }
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for PutRequest {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for PutRequest {
        #[inline]
        fn eq(&self, other: &PutRequest) -> bool {
            self.key == other.key && self.data == other.data
        }
    }
    impl ::prost::Message for PutRequest {
        #[allow(unused_variables)]
        fn encode_raw(&self, buf: &mut impl ::prost::bytes::BufMut) {
            if self.key != "" {
                ::prost::encoding::string::encode(1u32, &self.key, buf);
            }
            if self.data != b"" as &[u8] {
                ::prost::encoding::bytes::encode(2u32, &self.data, buf);
            }
        }
        #[allow(unused_variables)]
        fn merge_field(
            &mut self,
            tag: u32,
            wire_type: ::prost::encoding::wire_type::WireType,
            buf: &mut impl ::prost::bytes::Buf,
            ctx: ::prost::encoding::DecodeContext,
        ) -> ::core::result::Result<(), ::prost::DecodeError> {
            const STRUCT_NAME: &'static str = "PutRequest";
            match tag {
                1u32 => {
                    let mut value = &mut self.key;
                    ::prost::encoding::string::merge(wire_type, value, buf, ctx)
                        .map_err(|mut error| {
                            error.push(STRUCT_NAME, "key");
                            error
                        })
                }
                2u32 => {
                    let mut value = &mut self.data;
                    ::prost::encoding::bytes::merge(wire_type, value, buf, ctx)
                        .map_err(|mut error| {
                            error.push(STRUCT_NAME, "data");
                            error
                        })
                }
                _ => ::prost::encoding::skip_field(wire_type, tag, buf, ctx),
            }
        }
        #[inline]
        fn encoded_len(&self) -> usize {
            0
                + if self.key != "" {
                    ::prost::encoding::string::encoded_len(1u32, &self.key)
                } else {
                    0
                }
                + if self.data != b"" as &[u8] {
                    ::prost::encoding::bytes::encoded_len(2u32, &self.data)
                } else {
                    0
                }
        }
        fn clear(&mut self) {
            self.key.clear();
            self.data.clear();
        }
    }
    impl ::core::default::Default for PutRequest {
        fn default() -> Self {
            PutRequest {
                key: ::prost::alloc::string::String::new(),
                data: ::core::default::Default::default(),
            }
        }
    }
    impl ::core::fmt::Debug for PutRequest {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let mut builder = f.debug_struct("PutRequest");
            let builder = {
                let wrapper = {
                    #[allow(non_snake_case)]
                    fn ScalarWrapper<T>(v: T) -> T {
                        v
                    }
                    ScalarWrapper(&self.key)
                };
                builder.field("key", &wrapper)
            };
            let builder = {
                let wrapper = {
                    #[allow(non_snake_case)]
                    fn ScalarWrapper<T>(v: T) -> T {
                        v
                    }
                    ScalarWrapper(&self.data)
                };
                builder.field("data", &wrapper)
            };
            builder.finish()
        }
    }
    pub struct PutResponse {}
    #[automatically_derived]
    impl ::core::clone::Clone for PutResponse {
        #[inline]
        fn clone(&self) -> PutResponse {
            *self
        }
    }
    #[automatically_derived]
    impl ::core::marker::Copy for PutResponse {}
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for PutResponse {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for PutResponse {
        #[inline]
        fn eq(&self, other: &PutResponse) -> bool {
            true
        }
    }
    impl ::prost::Message for PutResponse {
        #[allow(unused_variables)]
        fn encode_raw(&self, buf: &mut impl ::prost::bytes::BufMut) {}
        #[allow(unused_variables)]
        fn merge_field(
            &mut self,
            tag: u32,
            wire_type: ::prost::encoding::wire_type::WireType,
            buf: &mut impl ::prost::bytes::Buf,
            ctx: ::prost::encoding::DecodeContext,
        ) -> ::core::result::Result<(), ::prost::DecodeError> {
            match tag {
                _ => ::prost::encoding::skip_field(wire_type, tag, buf, ctx),
            }
        }
        #[inline]
        fn encoded_len(&self) -> usize {
            0
        }
        fn clear(&mut self) {}
    }
    impl ::core::default::Default for PutResponse {
        fn default() -> Self {
            PutResponse {}
        }
    }
    impl ::core::fmt::Debug for PutResponse {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let mut builder = f.debug_struct("PutResponse");
            builder.finish()
        }
    }
    pub struct GetRequest {
        #[prost(string, tag = "1")]
        pub key: ::prost::alloc::string::String,
    }
    #[automatically_derived]
    impl ::core::clone::Clone for GetRequest {
        #[inline]
        fn clone(&self) -> GetRequest {
            GetRequest {
                key: ::core::clone::Clone::clone(&self.key),
            }
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for GetRequest {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for GetRequest {
        #[inline]
        fn eq(&self, other: &GetRequest) -> bool {
            self.key == other.key
        }
    }
    impl ::prost::Message for GetRequest {
        #[allow(unused_variables)]
        fn encode_raw(&self, buf: &mut impl ::prost::bytes::BufMut) {
            if self.key != "" {
                ::prost::encoding::string::encode(1u32, &self.key, buf);
            }
        }
        #[allow(unused_variables)]
        fn merge_field(
            &mut self,
            tag: u32,
            wire_type: ::prost::encoding::wire_type::WireType,
            buf: &mut impl ::prost::bytes::Buf,
            ctx: ::prost::encoding::DecodeContext,
        ) -> ::core::result::Result<(), ::prost::DecodeError> {
            const STRUCT_NAME: &'static str = "GetRequest";
            match tag {
                1u32 => {
                    let mut value = &mut self.key;
                    ::prost::encoding::string::merge(wire_type, value, buf, ctx)
                        .map_err(|mut error| {
                            error.push(STRUCT_NAME, "key");
                            error
                        })
                }
                _ => ::prost::encoding::skip_field(wire_type, tag, buf, ctx),
            }
        }
        #[inline]
        fn encoded_len(&self) -> usize {
            0
                + if self.key != "" {
                    ::prost::encoding::string::encoded_len(1u32, &self.key)
                } else {
                    0
                }
        }
        fn clear(&mut self) {
            self.key.clear();
        }
    }
    impl ::core::default::Default for GetRequest {
        fn default() -> Self {
            GetRequest {
                key: ::prost::alloc::string::String::new(),
            }
        }
    }
    impl ::core::fmt::Debug for GetRequest {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let mut builder = f.debug_struct("GetRequest");
            let builder = {
                let wrapper = {
                    #[allow(non_snake_case)]
                    fn ScalarWrapper<T>(v: T) -> T {
                        v
                    }
                    ScalarWrapper(&self.key)
                };
                builder.field("key", &wrapper)
            };
            builder.finish()
        }
    }
    pub struct GetResponse {
        #[prost(bytes = "vec", optional, tag = "1")]
        pub data: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    }
    #[automatically_derived]
    impl ::core::clone::Clone for GetResponse {
        #[inline]
        fn clone(&self) -> GetResponse {
            GetResponse {
                data: ::core::clone::Clone::clone(&self.data),
            }
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for GetResponse {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for GetResponse {
        #[inline]
        fn eq(&self, other: &GetResponse) -> bool {
            self.data == other.data
        }
    }
    impl ::prost::Message for GetResponse {
        #[allow(unused_variables)]
        fn encode_raw(&self, buf: &mut impl ::prost::bytes::BufMut) {
            if let ::core::option::Option::Some(ref value) = self.data {
                ::prost::encoding::bytes::encode(1u32, value, buf);
            }
        }
        #[allow(unused_variables)]
        fn merge_field(
            &mut self,
            tag: u32,
            wire_type: ::prost::encoding::wire_type::WireType,
            buf: &mut impl ::prost::bytes::Buf,
            ctx: ::prost::encoding::DecodeContext,
        ) -> ::core::result::Result<(), ::prost::DecodeError> {
            const STRUCT_NAME: &'static str = "GetResponse";
            match tag {
                1u32 => {
                    let mut value = &mut self.data;
                    ::prost::encoding::bytes::merge(
                            wire_type,
                            value.get_or_insert_with(::core::default::Default::default),
                            buf,
                            ctx,
                        )
                        .map_err(|mut error| {
                            error.push(STRUCT_NAME, "data");
                            error
                        })
                }
                _ => ::prost::encoding::skip_field(wire_type, tag, buf, ctx),
            }
        }
        #[inline]
        fn encoded_len(&self) -> usize {
            0
                + self
                    .data
                    .as_ref()
                    .map_or(
                        0,
                        |value| ::prost::encoding::bytes::encoded_len(1u32, value),
                    )
        }
        fn clear(&mut self) {
            self.data = ::core::option::Option::None;
        }
    }
    impl ::core::default::Default for GetResponse {
        fn default() -> Self {
            GetResponse {
                data: ::core::option::Option::None,
            }
        }
    }
    impl ::core::fmt::Debug for GetResponse {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let mut builder = f.debug_struct("GetResponse");
            let builder = {
                let wrapper = {
                    struct ScalarWrapper<'a>(
                        &'a ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
                    );
                    impl<'a> ::core::fmt::Debug for ScalarWrapper<'a> {
                        fn fmt(
                            &self,
                            f: &mut ::core::fmt::Formatter,
                        ) -> ::core::fmt::Result {
                            #[allow(non_snake_case)]
                            fn Inner<T>(v: T) -> T {
                                v
                            }
                            ::core::fmt::Debug::fmt(&self.0.as_ref().map(Inner), f)
                        }
                    }
                    ScalarWrapper(&self.data)
                };
                builder.field("data", &wrapper)
            };
            builder.finish()
        }
    }
    #[allow(dead_code)]
    impl GetResponse {
        ///Returns the value of `data`, or the default value if `data` is unset.
        pub fn data(&self) -> &[u8] {
            match self.data {
                ::core::option::Option::Some(ref val) => &val[..],
                ::core::option::Option::None => b"" as &[u8],
            }
        }
    }
    pub struct DeleteRequest {
        #[prost(string, tag = "1")]
        pub key: ::prost::alloc::string::String,
    }
    #[automatically_derived]
    impl ::core::clone::Clone for DeleteRequest {
        #[inline]
        fn clone(&self) -> DeleteRequest {
            DeleteRequest {
                key: ::core::clone::Clone::clone(&self.key),
            }
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for DeleteRequest {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for DeleteRequest {
        #[inline]
        fn eq(&self, other: &DeleteRequest) -> bool {
            self.key == other.key
        }
    }
    impl ::prost::Message for DeleteRequest {
        #[allow(unused_variables)]
        fn encode_raw(&self, buf: &mut impl ::prost::bytes::BufMut) {
            if self.key != "" {
                ::prost::encoding::string::encode(1u32, &self.key, buf);
            }
        }
        #[allow(unused_variables)]
        fn merge_field(
            &mut self,
            tag: u32,
            wire_type: ::prost::encoding::wire_type::WireType,
            buf: &mut impl ::prost::bytes::Buf,
            ctx: ::prost::encoding::DecodeContext,
        ) -> ::core::result::Result<(), ::prost::DecodeError> {
            const STRUCT_NAME: &'static str = "DeleteRequest";
            match tag {
                1u32 => {
                    let mut value = &mut self.key;
                    ::prost::encoding::string::merge(wire_type, value, buf, ctx)
                        .map_err(|mut error| {
                            error.push(STRUCT_NAME, "key");
                            error
                        })
                }
                _ => ::prost::encoding::skip_field(wire_type, tag, buf, ctx),
            }
        }
        #[inline]
        fn encoded_len(&self) -> usize {
            0
                + if self.key != "" {
                    ::prost::encoding::string::encoded_len(1u32, &self.key)
                } else {
                    0
                }
        }
        fn clear(&mut self) {
            self.key.clear();
        }
    }
    impl ::core::default::Default for DeleteRequest {
        fn default() -> Self {
            DeleteRequest {
                key: ::prost::alloc::string::String::new(),
            }
        }
    }
    impl ::core::fmt::Debug for DeleteRequest {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let mut builder = f.debug_struct("DeleteRequest");
            let builder = {
                let wrapper = {
                    #[allow(non_snake_case)]
                    fn ScalarWrapper<T>(v: T) -> T {
                        v
                    }
                    ScalarWrapper(&self.key)
                };
                builder.field("key", &wrapper)
            };
            builder.finish()
        }
    }
    pub struct DeleteResponse {}
    #[automatically_derived]
    impl ::core::clone::Clone for DeleteResponse {
        #[inline]
        fn clone(&self) -> DeleteResponse {
            *self
        }
    }
    #[automatically_derived]
    impl ::core::marker::Copy for DeleteResponse {}
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for DeleteResponse {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for DeleteResponse {
        #[inline]
        fn eq(&self, other: &DeleteResponse) -> bool {
            true
        }
    }
    impl ::prost::Message for DeleteResponse {
        #[allow(unused_variables)]
        fn encode_raw(&self, buf: &mut impl ::prost::bytes::BufMut) {}
        #[allow(unused_variables)]
        fn merge_field(
            &mut self,
            tag: u32,
            wire_type: ::prost::encoding::wire_type::WireType,
            buf: &mut impl ::prost::bytes::Buf,
            ctx: ::prost::encoding::DecodeContext,
        ) -> ::core::result::Result<(), ::prost::DecodeError> {
            match tag {
                _ => ::prost::encoding::skip_field(wire_type, tag, buf, ctx),
            }
        }
        #[inline]
        fn encoded_len(&self) -> usize {
            0
        }
        fn clear(&mut self) {}
    }
    impl ::core::default::Default for DeleteResponse {
        fn default() -> Self {
            DeleteResponse {}
        }
    }
    impl ::core::fmt::Debug for DeleteResponse {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let mut builder = f.debug_struct("DeleteResponse");
            builder.finish()
        }
    }
    /// Generated client implementations.
    pub mod blob_store_client {
        #![allow(
            unused_variables,
            dead_code,
            missing_docs,
            clippy::wildcard_imports,
            clippy::let_unit_value,
        )]
        use tonic::codegen::*;
        use tonic::codegen::http::Uri;
        pub struct BlobStoreClient<T> {
            inner: tonic::client::Grpc<T>,
        }
        #[automatically_derived]
        impl<T: ::core::fmt::Debug> ::core::fmt::Debug for BlobStoreClient<T> {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "BlobStoreClient",
                    "inner",
                    &&self.inner,
                )
            }
        }
        #[automatically_derived]
        impl<T: ::core::clone::Clone> ::core::clone::Clone for BlobStoreClient<T> {
            #[inline]
            fn clone(&self) -> BlobStoreClient<T> {
                BlobStoreClient {
                    inner: ::core::clone::Clone::clone(&self.inner),
                }
            }
        }
        impl BlobStoreClient<tonic::transport::Channel> {
            /// Attempt to create a new client by connecting to a given endpoint.
            pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
            where
                D: TryInto<tonic::transport::Endpoint>,
                D::Error: Into<StdError>,
            {
                let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
                Ok(Self::new(conn))
            }
        }
        impl<T> BlobStoreClient<T>
        where
            T: tonic::client::GrpcService<tonic::body::Body>,
            T::Error: Into<StdError>,
            T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
            <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
        {
            pub fn new(inner: T) -> Self {
                let inner = tonic::client::Grpc::new(inner);
                Self { inner }
            }
            pub fn with_origin(inner: T, origin: Uri) -> Self {
                let inner = tonic::client::Grpc::with_origin(inner, origin);
                Self { inner }
            }
            pub fn with_interceptor<F>(
                inner: T,
                interceptor: F,
            ) -> BlobStoreClient<InterceptedService<T, F>>
            where
                F: tonic::service::Interceptor,
                T::ResponseBody: Default,
                T: tonic::codegen::Service<
                    http::Request<tonic::body::Body>,
                    Response = http::Response<
                        <T as tonic::client::GrpcService<
                            tonic::body::Body,
                        >>::ResponseBody,
                    >,
                >,
                <T as tonic::codegen::Service<
                    http::Request<tonic::body::Body>,
                >>::Error: Into<StdError> + std::marker::Send + std::marker::Sync,
            {
                BlobStoreClient::new(InterceptedService::new(inner, interceptor))
            }
            /// Compress requests with the given encoding.
            ///
            /// This requires the server to support it otherwise it might respond with an
            /// error.
            #[must_use]
            pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
                self.inner = self.inner.send_compressed(encoding);
                self
            }
            /// Enable decompressing responses.
            #[must_use]
            pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
                self.inner = self.inner.accept_compressed(encoding);
                self
            }
            /// Limits the maximum size of a decoded message.
            ///
            /// Default: `4MB`
            #[must_use]
            pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
                self.inner = self.inner.max_decoding_message_size(limit);
                self
            }
            /// Limits the maximum size of an encoded message.
            ///
            /// Default: `usize::MAX`
            #[must_use]
            pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
                self.inner = self.inner.max_encoding_message_size(limit);
                self
            }
            pub async fn put(
                &mut self,
                request: impl tonic::IntoRequest<super::PutRequest>,
            ) -> std::result::Result<
                tonic::Response<super::PutResponse>,
                tonic::Status,
            > {
                self.inner
                    .ready()
                    .await
                    .map_err(|e| {
                        tonic::Status::unknown(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!("Service was not ready: {0}", e.into()),
                                )
                            }),
                        )
                    })?;
                let codec = tonic::codec::ProstCodec::default();
                let path = http::uri::PathAndQuery::from_static(
                    "/enclavid.store.BlobStore/Put",
                );
                let mut req = request.into_request();
                req.extensions_mut()
                    .insert(GrpcMethod::new("enclavid.store.BlobStore", "Put"));
                self.inner.unary(req, path, codec).await
            }
            pub async fn get(
                &mut self,
                request: impl tonic::IntoRequest<super::GetRequest>,
            ) -> std::result::Result<
                tonic::Response<super::GetResponse>,
                tonic::Status,
            > {
                self.inner
                    .ready()
                    .await
                    .map_err(|e| {
                        tonic::Status::unknown(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!("Service was not ready: {0}", e.into()),
                                )
                            }),
                        )
                    })?;
                let codec = tonic::codec::ProstCodec::default();
                let path = http::uri::PathAndQuery::from_static(
                    "/enclavid.store.BlobStore/Get",
                );
                let mut req = request.into_request();
                req.extensions_mut()
                    .insert(GrpcMethod::new("enclavid.store.BlobStore", "Get"));
                self.inner.unary(req, path, codec).await
            }
            pub async fn delete(
                &mut self,
                request: impl tonic::IntoRequest<super::DeleteRequest>,
            ) -> std::result::Result<
                tonic::Response<super::DeleteResponse>,
                tonic::Status,
            > {
                self.inner
                    .ready()
                    .await
                    .map_err(|e| {
                        tonic::Status::unknown(
                            ::alloc::__export::must_use({
                                ::alloc::fmt::format(
                                    format_args!("Service was not ready: {0}", e.into()),
                                )
                            }),
                        )
                    })?;
                let codec = tonic::codec::ProstCodec::default();
                let path = http::uri::PathAndQuery::from_static(
                    "/enclavid.store.BlobStore/Delete",
                );
                let mut req = request.into_request();
                req.extensions_mut()
                    .insert(GrpcMethod::new("enclavid.store.BlobStore", "Delete"));
                self.inner.unary(req, path, codec).await
            }
        }
    }
    /// Generated server implementations.
    pub mod blob_store_server {
        #![allow(
            unused_variables,
            dead_code,
            missing_docs,
            clippy::wildcard_imports,
            clippy::let_unit_value,
        )]
        use tonic::codegen::*;
        /// Generated trait containing gRPC methods that should be implemented for use with BlobStoreServer.
        pub trait BlobStore: std::marker::Send + std::marker::Sync + 'static {
            #[must_use]
            #[allow(
                elided_named_lifetimes,
                clippy::type_complexity,
                clippy::type_repetition_in_bounds
            )]
            fn put<'life0, 'async_trait>(
                &'life0 self,
                request: tonic::Request<super::PutRequest>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<
                        Output = std::result::Result<
                            tonic::Response<super::PutResponse>,
                            tonic::Status,
                        >,
                    > + ::core::marker::Send + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                Self: 'async_trait;
            #[must_use]
            #[allow(
                elided_named_lifetimes,
                clippy::type_complexity,
                clippy::type_repetition_in_bounds
            )]
            fn get<'life0, 'async_trait>(
                &'life0 self,
                request: tonic::Request<super::GetRequest>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<
                        Output = std::result::Result<
                            tonic::Response<super::GetResponse>,
                            tonic::Status,
                        >,
                    > + ::core::marker::Send + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                Self: 'async_trait;
            #[must_use]
            #[allow(
                elided_named_lifetimes,
                clippy::type_complexity,
                clippy::type_repetition_in_bounds
            )]
            fn delete<'life0, 'async_trait>(
                &'life0 self,
                request: tonic::Request<super::DeleteRequest>,
            ) -> ::core::pin::Pin<
                Box<
                    dyn ::core::future::Future<
                        Output = std::result::Result<
                            tonic::Response<super::DeleteResponse>,
                            tonic::Status,
                        >,
                    > + ::core::marker::Send + 'async_trait,
                >,
            >
            where
                'life0: 'async_trait,
                Self: 'async_trait;
        }
        pub struct BlobStoreServer<T> {
            inner: Arc<T>,
            accept_compression_encodings: EnabledCompressionEncodings,
            send_compression_encodings: EnabledCompressionEncodings,
            max_decoding_message_size: Option<usize>,
            max_encoding_message_size: Option<usize>,
        }
        #[automatically_derived]
        impl<T: ::core::fmt::Debug> ::core::fmt::Debug for BlobStoreServer<T> {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field5_finish(
                    f,
                    "BlobStoreServer",
                    "inner",
                    &self.inner,
                    "accept_compression_encodings",
                    &self.accept_compression_encodings,
                    "send_compression_encodings",
                    &self.send_compression_encodings,
                    "max_decoding_message_size",
                    &self.max_decoding_message_size,
                    "max_encoding_message_size",
                    &&self.max_encoding_message_size,
                )
            }
        }
        impl<T> BlobStoreServer<T> {
            pub fn new(inner: T) -> Self {
                Self::from_arc(Arc::new(inner))
            }
            pub fn from_arc(inner: Arc<T>) -> Self {
                Self {
                    inner,
                    accept_compression_encodings: Default::default(),
                    send_compression_encodings: Default::default(),
                    max_decoding_message_size: None,
                    max_encoding_message_size: None,
                }
            }
            pub fn with_interceptor<F>(
                inner: T,
                interceptor: F,
            ) -> InterceptedService<Self, F>
            where
                F: tonic::service::Interceptor,
            {
                InterceptedService::new(Self::new(inner), interceptor)
            }
            /// Enable decompressing requests with the given encoding.
            #[must_use]
            pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
                self.accept_compression_encodings.enable(encoding);
                self
            }
            /// Compress responses with the given encoding, if the client supports it.
            #[must_use]
            pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
                self.send_compression_encodings.enable(encoding);
                self
            }
            /// Limits the maximum size of a decoded message.
            ///
            /// Default: `4MB`
            #[must_use]
            pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
                self.max_decoding_message_size = Some(limit);
                self
            }
            /// Limits the maximum size of an encoded message.
            ///
            /// Default: `usize::MAX`
            #[must_use]
            pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
                self.max_encoding_message_size = Some(limit);
                self
            }
        }
        impl<T, B> tonic::codegen::Service<http::Request<B>> for BlobStoreServer<T>
        where
            T: BlobStore,
            B: Body + std::marker::Send + 'static,
            B::Error: Into<StdError> + std::marker::Send + 'static,
        {
            type Response = http::Response<tonic::body::Body>;
            type Error = std::convert::Infallible;
            type Future = BoxFuture<Self::Response, Self::Error>;
            fn poll_ready(
                &mut self,
                _cx: &mut Context<'_>,
            ) -> Poll<std::result::Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, req: http::Request<B>) -> Self::Future {
                match req.uri().path() {
                    "/enclavid.store.BlobStore/Put" => {
                        #[allow(non_camel_case_types)]
                        struct PutSvc<T: BlobStore>(pub Arc<T>);
                        impl<T: BlobStore> tonic::server::UnaryService<super::PutRequest>
                        for PutSvc<T> {
                            type Response = super::PutResponse;
                            type Future = BoxFuture<
                                tonic::Response<Self::Response>,
                                tonic::Status,
                            >;
                            fn call(
                                &mut self,
                                request: tonic::Request<super::PutRequest>,
                            ) -> Self::Future {
                                let inner = Arc::clone(&self.0);
                                let fut = async move {
                                    <T as BlobStore>::put(&inner, request).await
                                };
                                Box::pin(fut)
                            }
                        }
                        let accept_compression_encodings = self
                            .accept_compression_encodings;
                        let send_compression_encodings = self.send_compression_encodings;
                        let max_decoding_message_size = self.max_decoding_message_size;
                        let max_encoding_message_size = self.max_encoding_message_size;
                        let inner = self.inner.clone();
                        let fut = async move {
                            let method = PutSvc(inner);
                            let codec = tonic::codec::ProstCodec::default();
                            let mut grpc = tonic::server::Grpc::new(codec)
                                .apply_compression_config(
                                    accept_compression_encodings,
                                    send_compression_encodings,
                                )
                                .apply_max_message_size_config(
                                    max_decoding_message_size,
                                    max_encoding_message_size,
                                );
                            let res = grpc.unary(method, req).await;
                            Ok(res)
                        };
                        Box::pin(fut)
                    }
                    "/enclavid.store.BlobStore/Get" => {
                        #[allow(non_camel_case_types)]
                        struct GetSvc<T: BlobStore>(pub Arc<T>);
                        impl<T: BlobStore> tonic::server::UnaryService<super::GetRequest>
                        for GetSvc<T> {
                            type Response = super::GetResponse;
                            type Future = BoxFuture<
                                tonic::Response<Self::Response>,
                                tonic::Status,
                            >;
                            fn call(
                                &mut self,
                                request: tonic::Request<super::GetRequest>,
                            ) -> Self::Future {
                                let inner = Arc::clone(&self.0);
                                let fut = async move {
                                    <T as BlobStore>::get(&inner, request).await
                                };
                                Box::pin(fut)
                            }
                        }
                        let accept_compression_encodings = self
                            .accept_compression_encodings;
                        let send_compression_encodings = self.send_compression_encodings;
                        let max_decoding_message_size = self.max_decoding_message_size;
                        let max_encoding_message_size = self.max_encoding_message_size;
                        let inner = self.inner.clone();
                        let fut = async move {
                            let method = GetSvc(inner);
                            let codec = tonic::codec::ProstCodec::default();
                            let mut grpc = tonic::server::Grpc::new(codec)
                                .apply_compression_config(
                                    accept_compression_encodings,
                                    send_compression_encodings,
                                )
                                .apply_max_message_size_config(
                                    max_decoding_message_size,
                                    max_encoding_message_size,
                                );
                            let res = grpc.unary(method, req).await;
                            Ok(res)
                        };
                        Box::pin(fut)
                    }
                    "/enclavid.store.BlobStore/Delete" => {
                        #[allow(non_camel_case_types)]
                        struct DeleteSvc<T: BlobStore>(pub Arc<T>);
                        impl<
                            T: BlobStore,
                        > tonic::server::UnaryService<super::DeleteRequest>
                        for DeleteSvc<T> {
                            type Response = super::DeleteResponse;
                            type Future = BoxFuture<
                                tonic::Response<Self::Response>,
                                tonic::Status,
                            >;
                            fn call(
                                &mut self,
                                request: tonic::Request<super::DeleteRequest>,
                            ) -> Self::Future {
                                let inner = Arc::clone(&self.0);
                                let fut = async move {
                                    <T as BlobStore>::delete(&inner, request).await
                                };
                                Box::pin(fut)
                            }
                        }
                        let accept_compression_encodings = self
                            .accept_compression_encodings;
                        let send_compression_encodings = self.send_compression_encodings;
                        let max_decoding_message_size = self.max_decoding_message_size;
                        let max_encoding_message_size = self.max_encoding_message_size;
                        let inner = self.inner.clone();
                        let fut = async move {
                            let method = DeleteSvc(inner);
                            let codec = tonic::codec::ProstCodec::default();
                            let mut grpc = tonic::server::Grpc::new(codec)
                                .apply_compression_config(
                                    accept_compression_encodings,
                                    send_compression_encodings,
                                )
                                .apply_max_message_size_config(
                                    max_decoding_message_size,
                                    max_encoding_message_size,
                                );
                            let res = grpc.unary(method, req).await;
                            Ok(res)
                        };
                        Box::pin(fut)
                    }
                    _ => {
                        Box::pin(async move {
                            let mut response = http::Response::new(
                                tonic::body::Body::default(),
                            );
                            let headers = response.headers_mut();
                            headers
                                .insert(
                                    tonic::Status::GRPC_STATUS,
                                    (tonic::Code::Unimplemented as i32).into(),
                                );
                            headers
                                .insert(
                                    http::header::CONTENT_TYPE,
                                    tonic::metadata::GRPC_CONTENT_TYPE,
                                );
                            Ok(response)
                        })
                    }
                }
            }
        }
        impl<T> Clone for BlobStoreServer<T> {
            fn clone(&self) -> Self {
                let inner = self.inner.clone();
                Self {
                    inner,
                    accept_compression_encodings: self.accept_compression_encodings,
                    send_compression_encodings: self.send_compression_encodings,
                    max_decoding_message_size: self.max_decoding_message_size,
                    max_encoding_message_size: self.max_encoding_message_size,
                }
            }
        }
        /// Generated gRPC service name
        pub const SERVICE_NAME: &str = "enclavid.store.BlobStore";
        impl<T> tonic::server::NamedService for BlobStoreServer<T> {
            const NAME: &'static str = SERVICE_NAME;
        }
    }
}
pub use cipher::{Cipher, CipherError, NoCipher};
pub use encrypted::EncryptedStore;
pub use error::StoreError;
pub use grpc::GrpcStore;
pub use self::serde::SerdeStore;
pub use store::Store;
