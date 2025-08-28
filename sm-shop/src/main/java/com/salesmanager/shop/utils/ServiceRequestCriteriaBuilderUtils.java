package com.salesmanager.shop.utils;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.PropertyAccessor;
import org.springframework.beans.PropertyAccessorFactory;

import com.salesmanager.core.model.common.Criteria;
import com.salesmanager.core.model.common.CriteriaOrderBy;
import com.salesmanager.core.model.merchant.MerchantStoreCriteria;
import com.salesmanager.shop.store.api.exception.RestApiException;

public class ServiceRequestCriteriaBuilderUtils {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(ServiceRequestCriteriaBuilderUtils.class);
	
	/**
	 * Binds request parameter values to specific request criterias
	 * @param criteria
	 * @param mappingFields
	 * @param request
	 * @return
	 * @throws Exception
	 */
	public static Criteria buildRequestCriterias(Criteria criteria, Map<String, String> mappingFields, HttpServletRequest request) throws RestApiException {
		
			if(criteria == null)
				throw new RestApiException("A criteria class type must be instantiated");
	
			mappingFields.keySet().stream().forEach(p -> {
				try {
					setValue(criteria, request, p, mappingFields.get(p));
				} catch (Exception e) {
					e.printStackTrace();
				}
			});
			return criteria;
		

		
	}
	
	// SECURITY FIX: Added input validation to prevent arbitrary property access
	private static void setValue(Criteria criteria, HttpServletRequest request, String parameterName, String setterValue) throws Exception {
		
		
		try {
			
			// SECURITY FIX: Validate setter name to prevent arbitrary property access
			if (setterValue == null || setterValue.trim().isEmpty()) {
				throw new Exception("Invalid setter name");
			}
			
			// Only allow specific property names to prevent arbitrary property access
			String[] allowedProperties = {"name", "firstName", "lastName", "email", "search", "orderBy", "maxCount", "startIndex"};
			boolean isAllowedProperty = false;
			for (String allowedProp : allowedProperties) {
				if (allowedProp.equals(setterValue)) {
					isAllowedProperty = true;
					break;
				}
			}
			if (!isAllowedProperty) {
				throw new Exception("Property access not allowed: " + setterValue);
			}
			
			PropertyAccessor criteriaAccessor = PropertyAccessorFactory.forDirectFieldAccess(criteria);
			
			
			String parameterValue = request.getParameter(parameterName);
			if(parameterValue == null) return;
			
			// SECURITY FIX: Sanitize input to prevent injection attacks
			parameterValue = sanitizeInput(parameterValue);
			
			// set the property directly, bypassing the mutator (if any)
			//String setterName = "set" + WordUtils.capitalize(setterValue);
			String setterName = setterValue;
			System.out.println("Trying to do this binding " + setterName + "('" + parameterValue + "') on " + criteria.getClass());
			criteriaAccessor.setPropertyValue(setterName, parameterValue);
		
		} catch(Exception e) {
			throw new Exception("An error occured while parameter bindding", e);
		}
		
		
	}
	
	// SECURITY FIX: Added input sanitization method
	private static String sanitizeInput(String input) {
		if (input == null) return null;
		// Remove potentially dangerous characters
		return input.replaceAll("[<>\"'&;]", "");
	}
		   
  /** deprecated **/
  public static Criteria buildRequest(Map<String, String> mappingFields, HttpServletRequest request) {
    
    /**
     * Works assuming datatable sends query data
     */
    MerchantStoreCriteria criteria = new MerchantStoreCriteria();

    String searchParam = request.getParameter("search[value]");
    String orderColums = request.getParameter("order[0][column]");

    if (!StringUtils.isBlank(orderColums)) {
      String columnName = request.getParameter("columns[" + orderColums + "][data]");
      String overwriteField = columnName;
      if (mappingFields != null && mappingFields.get(columnName) != null) {
        overwriteField = mappingFields.get(columnName);
      }
      criteria.setCriteriaOrderByField(overwriteField);
      criteria.setOrderBy(
          CriteriaOrderBy.valueOf(request.getParameter("order[0][dir]").toUpperCase()));
    }
    
    String storeName = request.getParameter("storeName");
    criteria.setName(storeName);
    
    String retailers = request.getParameter("retailers");
    String stores = request.getParameter("stores");
    
    try {
    	boolean retail = Boolean.valueOf(retailers);
    	boolean sto = Boolean.valueOf(stores);

        criteria.setRetailers(retail);
        criteria.setStores(sto);
    } catch(Exception e) {
    	LOGGER.error("Error parsing boolean values",e);
    }
    
    criteria.setSearch(searchParam);

    return criteria;
    
  }

}
