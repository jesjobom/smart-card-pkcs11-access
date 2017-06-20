package com.jesjobom.pkcs11.jna;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.PointerType;
import com.sun.jna.Structure;

/**
 * Mapping of a native structure used by the native library.
 * Since JNA doesn't work well with structures (it has some problems with random 
 * memory allocation) it is necessary to convert Java to Native and Native to Java.
 * Doing that we can achieve a single memory block with all the data correctly 
 * ordered.
 * <br>
 * Also, we need to verify the conversion of Long values since it needs 8 or 4 bytes
 * depending on the OS.
 * <br>
 * Got this idea from {@link https://github.com/joelhockey/jacknji11}
 *
 * @author jesjobom
 * @see http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc323024067
 * 
 */
public class CK_ATTRIBUTE {

	public long type;

	public byte[] pValue = null;

	public long ulValueLen = 0;

	public static class ByReference extends CK_ATTRIBUTE implements Structure.ByReference {
	}

	public static class ByValue extends CK_ATTRIBUTE implements Structure.ByValue {
	}

	public CK_ATTRIBUTE() {
	}

	public CK_ATTRIBUTE(long type) {
		this.type = type;
	}

	public CK_ATTRIBUTE(long type, long size) {
		this.type = type;
		this.ulValueLen = size;
		this.pValue = new byte[(int)size];
	}
	
	/**
	 * Inner class representing the single memory block with all the data 
	 * from the outter class.
	 */
	public static class Native extends PointerType {
		
		private CK_ATTRIBUTE[] attributes;
		
		private int offset = 0;

		public Native() {
			this(null);
		}

		/**
		 * Converts the data from the Java Object to a single memory block,
		 * keeping the original order.
		 * 
		 * @param attributes 
		 */
		public Native(CK_ATTRIBUTE[] attributes) {
			this.attributes = attributes;
			
			if (this.attributes == null || this.attributes.length == 0) {
				return;
			}
			
			int memorySize = this.attributes.length * (NativeLong.SIZE + NativeLong.SIZE + Pointer.SIZE);
			super.setPointer(new Memory(memorySize));
			
			offset = 0;
			
			for (CK_ATTRIBUTE attribute : attributes) {
				addLongToMemory(attribute.type);
				addBytesToMemory(attribute.pValue);
				addLongToMemory(attribute.ulValueLen);
			}
		}
		
		/**
		 * Converts this memory block into a array of Java Objects.
		 * 
		 * @return array of {@link CK_ATTRIBUTE}
		 */
		public CK_ATTRIBUTE[] refresh() {
			if(this.attributes == null || this.attributes.length == 0) {
				return null;
			}
			
			offset = 0;
			
			for (CK_ATTRIBUTE attribute : attributes) {
				attribute.type = getLongFromMemory();
				Pointer pointer = getPointerFromMemory();
				attribute.ulValueLen = getLongFromMemory();
				
				if(pointer != null) {
					attribute.pValue = getBytesFromMemory(pointer, (int)attribute.ulValueLen);
				}
			}
			
			return attributes;
		}
		
		private void addLongToMemory(long value) {
			if(NativeLong.SIZE == 4) {
				getPointer().setInt(offset, (int)value);
			} else {
				//NativeLong.SIZE == 8
				getPointer().setLong(offset, value);
			}
			offset += NativeLong.SIZE;
		}
		
		private long getLongFromMemory() {
			long value;
			if(NativeLong.SIZE == 4) {
				value = getPointer().getInt(offset);
			} else {
				//NativeLong.SIZE == 8
				value = getPointer().getLong(offset);
			}
			
			offset += NativeLong.SIZE;
			return value;
		}
		
		private void addBytesToMemory(byte[] bytes) {
			if(bytes == null || bytes.length == 0) {
				getPointer().setPointer(offset, Pointer.NULL);
			} else {
				Memory pValue = new Memory(bytes.length);
				pValue.write(0, bytes, 0, bytes.length);
				getPointer().setPointer(offset, pValue);
			}
			offset += Pointer.SIZE;
		}
		
		private Pointer getPointerFromMemory() {
			Pointer pointer = getPointer().getPointer(offset);
			offset += Pointer.SIZE;
			return pointer;
		}
		
		private byte[] getBytesFromMemory(Pointer pointer, int size) {
			byte[] bytes = new byte[size];
			pointer.read(0, bytes, 0, size);
			return bytes;
		}
	}
}
