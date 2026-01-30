/**
 * MOCK AADHAAR SERVICE
 * Simulates UIDAI verification without accessing real biometric data.
 * In a real scenario, this would be an external API call to a government endpoint.
 */

exports.verifyAadhaar = (aadhaarNumber) => {
    const aadhaarRegex = /^\d{12}$/;
    if (!aadhaarRegex.test(aadhaarNumber)) {
        return { isValid: false, message: 'Invalid Aadhaar format' };
    }

    if (aadhaarNumber === '000000000000') {
        return { isValid: false, message: 'Aadhaar does not exist' };
    }

    return { isValid: true, message: 'Aadhaar Verified' };
};

exports.generateMockOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};