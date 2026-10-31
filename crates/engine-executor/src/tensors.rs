//! The host's tensors, `enclavid:host/tensors`: a resource for each element
//! type, its dimensions and elements held in the round's table — minted by a
//! component's constructor, or by a model's `run` for each tensor the model
//! gives back — and what a `run` turns them into and out of: the tensors the
//! process a model runs in reads and writes.

use enclavid_inference::protocol::{Data, MAX_BYTES, MAX_RANK, Tensor};
use wasmtime::StoreContextMut;
use wasmtime::component::{Resource, ResourceAny, ResourceType};

use crate::enclavid::host::tensors as wit;
use crate::state::HostState;

/// That `dims` hold exactly `len` elements of `size` bytes, as many as one
/// tensor may: no more than [`MAX_RANK`] dimensions and [`MAX_BYTES`] of
/// elements, what a model's process reads. A tensor past either, or whose
/// dimensions hold another count, traps where it is made.
fn held(dims: &[u64], len: usize, size: usize) -> wasmtime::Result<()> {
    let elements = dims.iter().try_fold(1u64, |n, &d| n.checked_mul(d));
    let bytes = u64::try_from(len)
        .ok()
        .and_then(|len| len.checked_mul(size as u64));
    let fits = dims.len() <= MAX_RANK as usize
        && elements == u64::try_from(len).ok()
        && bytes.is_some_and(|bytes| bytes <= MAX_BYTES);
    if !fits {
        return Err(wasmtime::Error::msg(
            "a tensor whose dimensions do not hold its elements, or past what one may hold",
        ));
    }
    Ok(())
}

/// For each element type: the tensor the table holds, its host trait, and the
/// protocol's case for its elements.
macro_rules! tensors {
    ($($rep:ident($ty:ty, $host:ident, $case:ident)),* $(,)?) => {
        $(
            /// A tensor of the host's, as the round's table holds it.
            pub struct $rep {
                dims: Vec<u64>,
                data: Vec<$ty>,
            }

            impl wit::$host for HostState {
                async fn new(
                    &mut self,
                    dims: Vec<u64>,
                    data: Vec<$ty>,
                ) -> wasmtime::Result<Resource<$rep>> {
                    held(&dims, data.len(), size_of::<$ty>())?;
                    Ok(self.table.push($rep { dims, data })?)
                }

                async fn dims(&mut self, tensor: Resource<$rep>) -> wasmtime::Result<Vec<u64>> {
                    Ok(self.table.get(&tensor)?.dims.clone())
                }

                async fn data(&mut self, tensor: Resource<$rep>) -> wasmtime::Result<Vec<$ty>> {
                    Ok(self.table.get(&tensor)?.data.clone())
                }

                async fn drop(&mut self, tensor: Resource<$rep>) -> wasmtime::Result<()> {
                    self.table.delete(tensor)?;
                    Ok(())
                }
            }
        )*

        /// The tensor `handle` names, as the protocol carries it: its
        /// dimensions and a copy of its elements. Taking it lets go of a
        /// borrow, as a dynamic host function must of every handle it is
        /// given. Not a tensor of the host's, it traps.
        pub(crate) fn lift(
            store: &mut StoreContextMut<'_, HostState>,
            handle: ResourceAny,
        ) -> wasmtime::Result<Tensor> {
            $(
                if handle.ty() == ResourceType::host::<$rep>() {
                    let tensor: Resource<$rep> = handle.try_into_resource(&mut *store)?;
                    let tensor = store.data().table.get(&tensor)?;
                    return Ok(Tensor {
                        dims: tensor.dims.clone(),
                        data: Data::$case(tensor.data.clone()),
                    });
                }
            )*
            Err(wasmtime::Error::msg("a handle of no tensor of the host's"))
        }

        /// `tensor`, as a tensor of the host's of the type `ty` a `run`
        /// returns, minted into the round's table. A tensor of another element
        /// type than `ty` traps: the model gave what its `run` does not return.
        pub(crate) fn mint(
            store: &mut StoreContextMut<'_, HostState>,
            ty: ResourceType,
            tensor: Tensor,
        ) -> wasmtime::Result<ResourceAny> {
            let Tensor { dims, data } = tensor;
            match data {
                $(
                    Data::$case(data) if ty == ResourceType::host::<$rep>() => {
                        let tensor = store.data_mut().table.push($rep { dims, data })?;
                        tensor.try_into_resource_any(&mut *store)
                    }
                )*
                _ => Err(wasmtime::Error::msg(
                    "the model gave a tensor of another element type than its run returns",
                )),
            }
        }
    };
}

tensors! {
    TensorF32(f32, HostTensorF32, F32),
    TensorF64(f64, HostTensorF64, F64),
    TensorF16(u16, HostTensorF16, F16),
    TensorBf16(u16, HostTensorBf16, Bf16),
    TensorI8(i8, HostTensorI8, I8),
    TensorU8(u8, HostTensorU8, U8),
    TensorI16(i16, HostTensorI16, I16),
    TensorU16(u16, HostTensorU16, U16),
    TensorI32(i32, HostTensorI32, I32),
    TensorU32(u32, HostTensorU32, U32),
    TensorI64(i64, HostTensorI64, I64),
    TensorU64(u64, HostTensorU64, U64),
}

impl wit::Host for HostState {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tensor is held where its dimensions hold its elements — a scalar's
    /// none hold one — within the rank and the bytes one may have.
    #[test]
    fn a_tensor_is_held_where_its_dimensions_hold_its_elements() {
        assert!(held(&[2, 3], 6, 4).is_ok());
        assert!(held(&[], 1, 4).is_ok());
        assert!(held(&[0, 7], 0, 4).is_ok());
        assert!(held(&[2, 3], 5, 4).is_err());
        assert!(held(&[u64::MAX, 2], 0, 4).is_err());
        assert!(held(&[1; MAX_RANK as usize + 1], 1, 4).is_err());
        let past = (MAX_BYTES / 4 + 1) as usize;
        assert!(held(&[past as u64], past, 4).is_err());
        assert!(held(&[past as u64], past, 1).is_ok());
    }
}
