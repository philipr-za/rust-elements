// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl $crate::encode::Encodable for $thing {
            #[inline]
            fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, $crate::encode::Error> {
                let mut ret = 0;
                $( ret += self.$field.consensus_encode(&mut s)?; )+
                Ok(ret)
            }
        }

        impl $crate::encode::Decodable for $thing {
            #[inline]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<$thing, $crate::encode::Error> {
                Ok($thing {
                    $( $field: $crate::encode::Decodable::consensus_decode(&mut d)?, )+
                })
            }
        }
    );
}

macro_rules! serde_struct_impl {
    ($name:ident, $($fe:ident),*) => (
        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                use std::fmt::{self, Formatter};
                use $crate::serde::de::IgnoredAny;

                #[allow(non_camel_case_types)]
                enum Enum { Unknown__Field, $($fe),* }

                struct EnumVisitor;
                impl<'de> $crate::serde::de::Visitor<'de> for EnumVisitor {
                    type Value = Enum;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("a field name")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        match v {
                            $(
                            stringify!($fe) => Ok(Enum::$fe)
                            ),*,
                            _ => Ok(Enum::Unknown__Field)
                        }
                    }
                }

                impl<'de> $crate::serde::Deserialize<'de> for Enum {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: ::serde::de::Deserializer<'de>,
                    {
                        deserializer.deserialize_str(EnumVisitor)
                    }
                }

                struct Visitor;

                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("a struct")
                    }

                    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                    where
                        A: $crate::serde::de::MapAccess<'de>,
                    {
                        use $crate::serde::de::Error;

                        $(let mut $fe = None;)*

                        loop {
                            match map.next_key::<Enum>()? {
                                Some(Enum::Unknown__Field) => {
                                    map.next_value::<IgnoredAny>()?;
                                }
                                $(
                                    Some(Enum::$fe) => {
                                        $fe = Some(map.next_value()?);
                                    }
                                )*
                                None => { break; }
                            }
                        }

                        $(
                            let $fe = match $fe {
                                Some(x) => x,
                                None => return Err(A::Error::missing_field(stringify!($fe))),
                            };
                        )*

                        let ret = $name {
                            $($fe),*
                        };

                        Ok(ret)
                    }
                }
                // end type defs

                static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                deserializer.deserialize_struct(stringify!($name), FIELDS, Visitor)
            }
        }

        #[cfg(feature = "serde")]
        impl $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                use $crate::serde::ser::SerializeStruct;

                // Only used to get the struct length.
                static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                let mut st = serializer.serialize_struct(stringify!($name), FIELDS.len())?;

                $(
                    st.serialize_field(stringify!($fe), &self.$fe)?;
                )*

                st.end()
            }
        }
    )
}

macro_rules! serde_string_impl {
    ($name:ident, $expecting:expr) => {
        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                use ::std::fmt::{self, Formatter};
                use ::std::str::FromStr;

                struct Visitor;
                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str($expecting)
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        $name::from_str(v).map_err(E::custom)
                    }

                    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        self.visit_str(v)
                    }

                    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        self.visit_str(&v)
                    }
                }

                deserializer.deserialize_str(Visitor)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                serializer.collect_str(&self)
            }
        }
    };
}

/// A combination of serde_struct_impl and serde_string_impl where string is
/// used for human-readable serialization and struct is used for
/// non-human-readable serialization.
macro_rules! serde_struct_human_string_impl {
    ($name:ident, $expecting:expr, $($fe:ident),*) => (
        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    use ::std::fmt::{self, Formatter};
                    use ::std::str::FromStr;

                    struct Visitor;
                    impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                        type Value = $name;

                        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                            formatter.write_str($expecting)
                        }

                        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            $name::from_str(v).map_err(E::custom)
                        }

                        fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            self.visit_str(v)
                        }

                        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            self.visit_str(&v)
                        }
                    }

                    deserializer.deserialize_str(Visitor)
                } else {
                    use ::std::fmt::{self, Formatter};
                    use $crate::serde::de::IgnoredAny;

                    #[allow(non_camel_case_types)]
                    enum Enum { Unknown__Field, $($fe),* }

                    struct EnumVisitor;
                    impl<'de> $crate::serde::de::Visitor<'de> for EnumVisitor {
                        type Value = Enum;

                        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                            formatter.write_str("a field name")
                        }

                        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            match v {
                                $(
                                stringify!($fe) => Ok(Enum::$fe)
                                ),*,
                                _ => Ok(Enum::Unknown__Field)
                            }
                        }
                    }

                    impl<'de> $crate::serde::Deserialize<'de> for Enum {
                        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                        where
                            D: $crate::serde::de::Deserializer<'de>,
                        {
                            deserializer.deserialize_str(EnumVisitor)
                        }
                    }

                    struct Visitor;

                    impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                        type Value = $name;

                        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                            formatter.write_str("a struct")
                        }

                        fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
                        where
                            V: $crate::serde::de::SeqAccess<'de>,
                        {
                            use $crate::serde::de::Error;

                            let length = 0;
                            $(
                                let $fe = seq.next_element()?.ok_or_else(|| {
                                    Error::invalid_length(length, &self)
                                })?;
                                #[allow(unused_variables)]
                                let length = length + 1;
                            )*

                            let ret = $name {
                                $($fe),*
                            };

                            Ok(ret)
                        }

                        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                        where
                            A: $crate::serde::de::MapAccess<'de>,
                        {
                            use $crate::serde::de::Error;

                            $(let mut $fe = None;)*

                            loop {
                                match map.next_key::<Enum>()? {
                                    Some(Enum::Unknown__Field) => {
                                        map.next_value::<IgnoredAny>()?;
                                    }
                                    $(
                                        Some(Enum::$fe) => {
                                            $fe = Some(map.next_value()?);
                                        }
                                    )*
                                    None => { break; }
                                }
                            }

                            $(
                                let $fe = match $fe {
                                    Some(x) => x,
                                    None => return Err(A::Error::missing_field(stringify!($fe))),
                                };
                            )*

                            let ret = $name {
                                $($fe),*
                            };

                            Ok(ret)
                        }
                    }
                    // end type defs

                    static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                    deserializer.deserialize_struct(stringify!($name), FIELDS, Visitor)
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.collect_str(&self)
                } else {
                    use $crate::serde::ser::SerializeStruct;

                    // Only used to get the struct length.
                    static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                    let mut st = serializer.serialize_struct(stringify!($name), FIELDS.len())?;

                    $(
                        st.serialize_field(stringify!($fe), &self.$fe)?;
                    )*

                    st.end()
                }
            }
        }
    )
}

#[cfg(test)]
macro_rules! hex_deserialize(
    ($e:expr) => ({
        use $crate::encode::deserialize;

        fn hex_char(c: char) -> u8 {
            match c {
                '0' => 0,
                '1' => 1,
                '2' => 2,
                '3' => 3,
                '4' => 4,
                '5' => 5,
                '6' => 6,
                '7' => 7,
                '8' => 8,
                '9' => 9,
                'a' | 'A' => 10,
                'b' | 'B' => 11,
                'c' | 'C' => 12,
                'd' | 'D' => 13,
                'e' | 'E' => 14,
                'f' | 'F' => 15,
                x => panic!("Invalid character {} in hex string", x),
            }
        }

        let mut ret = Vec::with_capacity($e.len() / 2);
        let mut byte = 0;
        for (ch, store) in $e.chars().zip([false, true].iter().cycle()) {
            byte = (byte << 4) + hex_char(ch);
            if *store {
                ret.push(byte);
                byte = 0;
            }
        }
        deserialize(&ret).expect("deserialize object")
    });
);

#[cfg(test)]
macro_rules! hex_script(
    ($e:expr) => ({
        let v: Vec<u8> = crate::hex::FromHex::from_hex($e)
            .expect("hex decoding");
        crate::Script::from(v)
    })
);

/// Implements standard array methods for a given wrapper type
macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:literal) => {
        impl $thing {
            /// Converts the object to a raw pointer.
            #[inline]
            pub fn as_ptr(&self) -> *const $ty {
                let &$thing(ref dat) = self;
                dat.as_ptr()
            }

            /// Converts the object to a mutable raw pointer.
            #[inline]
            pub fn as_mut_ptr(&mut self) -> *mut $ty {
                let &mut $thing(ref mut dat) = self;
                dat.as_mut_ptr()
            }

            /// Returns the length of the object as an array.
            #[inline]
            pub fn len(&self) -> usize { $len }

            /// Returns whether the object, as an array, is empty. Always false.
            #[inline]
            pub fn is_empty(&self) -> bool { false }
        }

        impl<'a> core::convert::From<[$ty; $len]> for $thing {
            fn from(data: [$ty; $len]) -> Self { $thing(data) }
        }

        impl<'a> core::convert::From<&'a [$ty; $len]> for $thing {
            fn from(data: &'a [$ty; $len]) -> Self { $thing(*data) }
        }

        impl<'a> core::convert::TryFrom<&'a [$ty]> for $thing {
            type Error = core::array::TryFromSliceError;

            fn try_from(data: &'a [$ty]) -> core::result::Result<Self, Self::Error> {
                use core::convert::TryInto;

                Ok($thing(data.try_into()?))
            }
        }

        impl AsRef<[$ty; $len]> for $thing {
            fn as_ref(&self) -> &[$ty; $len] { &self.0 }
        }

        impl AsMut<[$ty; $len]> for $thing {
            fn as_mut(&mut self) -> &mut [$ty; $len] { &mut self.0 }
        }

        impl AsRef<[$ty]> for $thing {
            fn as_ref(&self) -> &[$ty] { &self.0 }
        }

        impl AsMut<[$ty]> for $thing {
            fn as_mut(&mut self) -> &mut [$ty] { &mut self.0 }
        }

        impl core::borrow::Borrow<[$ty; $len]> for $thing {
            fn borrow(&self) -> &[$ty; $len] { &self.0 }
        }

        impl core::borrow::BorrowMut<[$ty; $len]> for $thing {
            fn borrow_mut(&mut self) -> &mut [$ty; $len] { &mut self.0 }
        }

        // The following two are valid because `[T; N]: Borrow<[T]>`
        impl core::borrow::Borrow<[$ty]> for $thing {
            fn borrow(&self) -> &[$ty] { &self.0 }
        }

        impl core::borrow::BorrowMut<[$ty]> for $thing {
            fn borrow_mut(&mut self) -> &mut [$ty] { &mut self.0 }
        }

        impl<I> core::ops::Index<I> for $thing
        where
            [$ty]: core::ops::Index<I>,
        {
            type Output = <[$ty] as core::ops::Index<I>>::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output { &self.0[index] }
        }
    };
}

/// Implements several traits for byte-based newtypes.
/// Implements:
/// - core::fmt::LowerHex
/// - core::fmt::UpperHex
/// - core::fmt::Display
/// - core::str::FromStr
macro_rules! impl_bytes_newtype {
    ($t:ident, $len:literal) => {
        impl $t {
            /// Returns a reference the underlying bytes.
            #[inline]
            pub fn as_bytes(&self) -> &[u8; $len] { &self.0 }

            /// Returns the underlying bytes.
            #[inline]
            pub fn to_bytes(self) -> [u8; $len] {
                // We rely on `Copy` being implemented for $t so conversion
                // methods use the correct Rust naming conventions.
                fn check_copy<T: Copy>() {}
                check_copy::<$t>();

                self.0
            }

            /// Creates `Self` from a hex string.
            pub fn from_hex(s: &str) -> Result<Self, hex::HexToArrayError> {
                Ok($t($crate::hex::FromHex::from_hex(s)?))
            }
        }

        impl core::fmt::LowerHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use $crate::hex::{display, Case};
                display::fmt_hex_exact!(f, $len, &self.0, Case::Lower)
            }
        }

        impl core::fmt::UpperHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use $crate::hex::{display, Case};
                display::fmt_hex_exact!(f, $len, &self.0, Case::Upper)
            }
        }

        impl core::fmt::Display for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                core::fmt::LowerHex::fmt(self, f)
            }
        }

        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                core::fmt::LowerHex::fmt(self, f)
            }
        }

        impl core::str::FromStr for $t {
            type Err = $crate::hex::HexToArrayError;
            fn from_str(s: &str) -> core::result::Result<Self, Self::Err> { Self::from_hex(s) }
        }

        #[cfg(feature = "serde")]
        impl $crate::serde::Serialize for $t {
            fn serialize<S: $crate::serde::Serializer>(
                &self,
                s: S,
            ) -> core::result::Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    s.collect_str(self)
                } else {
                    s.serialize_bytes(&self[..])
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $t {
            fn deserialize<D: $crate::serde::Deserializer<'de>>(
                d: D,
            ) -> core::result::Result<$t, D::Error> {
                if d.is_human_readable() {
                    struct HexVisitor;

                    impl<'de> $crate::serde::de::Visitor<'de> for HexVisitor {
                        type Value = $t;

                        fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                            f.write_str("an ASCII hex string")
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            use $crate::serde::de::Unexpected;

                            if let Ok(hex) = core::str::from_utf8(v) {
                                core::str::FromStr::from_str(hex).map_err(E::custom)
                            } else {
                                return Err(E::invalid_value(Unexpected::Bytes(v), &self));
                            }
                        }

                        fn visit_str<E>(self, hex: &str) -> core::result::Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            core::str::FromStr::from_str(hex).map_err(E::custom)
                        }
                    }

                    d.deserialize_str(HexVisitor)
                } else {
                    struct BytesVisitor;

                    impl<'de> $crate::serde::de::Visitor<'de> for BytesVisitor {
                        type Value = $t;

                        fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                            f.write_str("a bytestring")
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            if v.len() != $len {
                                Err(E::invalid_length(v.len(), &stringify!($len)))
                            } else {
                                let mut ret = [0; $len];
                                ret.copy_from_slice(v);
                                Ok($t(ret))
                            }
                        }
                    }

                    d.deserialize_bytes(BytesVisitor)
                }
            }
        }
    };
}